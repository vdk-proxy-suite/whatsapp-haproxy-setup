from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from config import load_config, render_haproxy, validate  # noqa: E402


def section(rendered: str, name: str) -> str:
    lines = rendered.splitlines()
    start = lines.index(name)
    end = next((index for index in range(start + 1, len(lines)) if not lines[index]), len(lines))
    return "\n".join(lines[start:end])


class HAProxyRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(str(ROOT / "config.example.yaml"))

    def test_legacy_route_less_render_is_byte_for_byte_stable(self) -> None:
        self.assertNotIn("routes", self.config)

        rendered = render_haproxy(self.config)

        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "daf9387acef3b7860d753e7587a85ce8416dc3a006c6fd9568b806abf57796b6",
        )
        self.assertNotIn("socks4", rendered)
        self.assertNotIn("check-via-socks4", rendered)

    def test_missing_backend_route_and_explicit_direct_keep_direct_render(self) -> None:
        legacy = render_haproxy(self.config)
        config = copy.deepcopy(self.config)
        config["routes"] = {"media": {"mode": "direct"}}

        self.assertEqual(render_haproxy(config), legacy)

    def test_media_socks4_route_is_inherited_only_by_media_servers(self) -> None:
        config = copy.deepcopy(self.config)
        config["routes"] = {
            "media": {
                "mode": "socks4",
                "socks4": {"host": "127.0.0.1", "port": 11081},
            },
        }

        rendered = render_haproxy(config)
        chat_backend = section(rendered, "backend whatsapp_chat")
        media_backend = section(rendered, "backend whatsapp_media")

        self.assertNotIn("socks4", chat_backend)
        self.assertIn(
            "default-server check inter 10s fastinter 2s downinter 30s "
            "rise 1 fall 2 observe layer4 socks4 127.0.0.1:11081 check-via-socks4",
            media_backend,
        )
        self.assertEqual(media_backend.count("socks4 127.0.0.1:11081"), 1)
        self.assertEqual(media_backend.count("check-via-socks4"), 1)
        self.assertEqual(media_backend.count("server-template whatsapp_net_443_"), 3)
        self.assertNotIn("send-proxy", media_backend)

    def test_chat_socks4_route_retains_proxy_v1_semantics(self) -> None:
        config = copy.deepcopy(self.config)
        config["routes"] = {
            "chat": {
                "mode": "socks4",
                "socks4": {"host": "127.0.0.1", "port": 11080},
            },
        }

        rendered = render_haproxy(config)
        chat_backend = section(rendered, "backend whatsapp_chat")
        media_backend = section(rendered, "backend whatsapp_media")

        self.assertIn(
            "observe layer4 send-proxy socks4 127.0.0.1:11080 check-via-socks4",
            chat_backend,
        )
        self.assertNotIn("send-proxy-v2", chat_backend)
        self.assertNotIn("socks4", media_backend)

    def test_socks4_route_applies_to_static_ipv4_server(self) -> None:
        config = copy.deepcopy(self.config)
        config["probes"]["media_upstream_host"] = "192.0.2.21"
        config["routes"] = {
            "media": {
                "mode": "socks4",
                "socks4": {"host": "127.0.0.1", "port": 11081},
            },
        }

        media_backend = section(render_haproxy(config), "backend whatsapp_media")

        self.assertIn("socks4 127.0.0.1:11081 check-via-socks4", media_backend)
        self.assertIn("server whatsapp_net_443 192.0.2.21:443", media_backend)
        self.assertNotIn("server-template", media_backend)

    def test_route_schema_rejects_invalid_shapes_and_modes(self) -> None:
        invalid_routes = (
            None,
            [],
            {"unknown": {"mode": "direct"}},
            {"media": []},
            {"media": {}},
            {"media": {"mode": "auto"}},
            {"media": {"mode": "direct", "socks4": {"host": "127.0.0.1", "port": 11081}}},
            {"media": {"mode": "socks4"}},
            {"media": {"mode": "socks4", "socks4": []}},
            {"media": {"mode": "socks4", "socks4": {"host": "127.0.0.1"}}},
            {"media": {"mode": "socks4", "socks4": {"port": 11081}}},
            {
                "media": {
                    "mode": "socks4",
                    "socks4": {"host": "127.0.0.1", "port": 11081, "username": "x"},
                },
            },
            {"media": {"mode": "direct", "fallback": "socks4"}},
        )

        for routes in invalid_routes:
            with self.subTest(routes=routes):
                config = copy.deepcopy(self.config)
                config["routes"] = routes
                with self.assertRaises(ValueError):
                    validate(config)

    def test_socks4_route_requires_exact_loopback_and_integer_port(self) -> None:
        invalid_hosts = ("localhost", "127.0.0.2", "0.0.0.0", "::1", "socks4://127.0.0.1")
        invalid_ports = (True, "11081", 0, 65536)

        for host in invalid_hosts:
            with self.subTest(host=host):
                config = copy.deepcopy(self.config)
                config["routes"] = {
                    "media": {
                        "mode": "socks4",
                        "socks4": {"host": host, "port": 11081},
                    },
                }
                with self.assertRaisesRegex(ValueError, "host must be exactly 127.0.0.1"):
                    validate(config)

        for port in invalid_ports:
            with self.subTest(port=port):
                config = copy.deepcopy(self.config)
                config["routes"] = {
                    "media": {
                        "mode": "socks4",
                        "socks4": {"host": "127.0.0.1", "port": port},
                    },
                }
                with self.assertRaisesRegex(ValueError, "port must be an integer from 1 to 65535"):
                    validate(config)

    def test_socks4_route_rejects_literal_ipv6_upstream(self) -> None:
        config = copy.deepcopy(self.config)
        config["probes"]["media_upstream_host"] = "2001:db8::1"
        config["routes"] = {
            "media": {
                "mode": "socks4",
                "socks4": {"host": "127.0.0.1", "port": 11081},
            },
        }

        with self.assertRaisesRegex(ValueError, "must resolve to IPv4 in socks4 mode"):
            validate(config)

    def test_upstream_ports_must_fit_tcp_port_range(self) -> None:
        config = copy.deepcopy(self.config)
        config["probes"]["media_upstream_port"] = 65536

        with self.assertRaisesRegex(ValueError, "outside the allowed range"):
            validate(config)

    def test_existing_yaml_enables_runtime_dns_without_new_keys(self) -> None:
        self.assertNotIn("dns", self.config)
        validate(self.config)

        rendered = render_haproxy(self.config)

        system_resolver = section(rendered, "resolvers whatsapp_dns_system")
        cloudflare_resolver = section(rendered, "resolvers whatsapp_dns_cloudflare")
        google_resolver = section(rendered, "resolvers whatsapp_dns_google")

        self.assertIn("parse-resolv-conf", system_resolver)
        self.assertNotIn("nameserver", system_resolver)
        self.assertIn("nameserver cloudflare_primary 1.1.1.1:53", cloudflare_resolver)
        self.assertIn("nameserver cloudflare_secondary 1.0.0.1:53", cloudflare_resolver)
        self.assertNotIn("parse-resolv-conf", cloudflare_resolver)
        self.assertNotIn("8.8.8.8", cloudflare_resolver)
        self.assertIn("nameserver google_primary 8.8.8.8:53", google_resolver)
        self.assertIn("nameserver google_secondary 8.8.4.4:53", google_resolver)
        self.assertNotIn("parse-resolv-conf", google_resolver)
        self.assertNotIn("1.1.1.1", google_resolver)
        self.assertEqual(rendered.count("hold obsolete 15m"), 3)

        dns_options = (
            "resolve-prefer ipv4 "
            "resolve-opts prevent-dup-ip init-addr last,none"
        )
        resolver_groups = (
            ("system", "whatsapp_dns_system"),
            ("cloudflare", "whatsapp_dns_cloudflare"),
            ("google", "whatsapp_dns_google"),
        )
        for view, resolver in resolver_groups:
            self.assertIn(
                f"server-template g_whatsapp_net_5222_{view} 4 "
                f"g.whatsapp.net:5222 resolvers {resolver} {dns_options}",
                rendered,
            )
            self.assertIn(
                f"server-template whatsapp_net_443_{view} 4 "
                f"whatsapp.net:443 resolvers {resolver} {dns_options}",
                rendered,
            )
        self.assertEqual(rendered.count("server-template"), 6)

    def test_critical_frontend_and_backend_semantics_are_unchanged(self) -> None:
        rendered = render_haproxy(self.config)
        chat_frontend = section(rendered, "frontend whatsapp_chat_tls")
        chat_backend = section(rendered, "backend whatsapp_chat")
        media_frontend = section(rendered, "frontend whatsapp_media")
        media_backend = section(rendered, "backend whatsapp_media")

        self.assertIn("bind 0.0.0.0:443 ssl crt", chat_frontend)
        self.assertIn("tcp-request connection set-dst ipv4(203.0.113.10)", chat_frontend)
        self.assertIn("default_backend whatsapp_chat", chat_frontend)
        self.assertIn("balance leastconn", chat_backend)
        self.assertIn(
            "default-server check inter 10s fastinter 2s downinter 30s "
            "rise 1 fall 2 observe layer4 send-proxy",
            chat_backend,
        )
        self.assertIn("observe layer4 send-proxy", chat_backend)
        self.assertNotIn("send-proxy-v2", chat_backend)

        self.assertIn("bind 0.0.0.0:587", media_frontend)
        self.assertNotIn(" ssl ", media_frontend)
        self.assertIn("default_backend whatsapp_media", media_frontend)
        self.assertIn("balance leastconn", media_backend)
        self.assertIn(
            "default-server check inter 10s fastinter 2s downinter 30s "
            "rise 1 fall 2 observe layer4",
            media_backend,
        )
        self.assertNotIn("send-proxy", media_backend)

    def test_literal_upstream_ips_stay_static(self) -> None:
        config = copy.deepcopy(self.config)
        config["probes"]["chat_upstream_host"] = "192.0.2.20"
        config["probes"]["media_upstream_host"] = "192.0.2.21"

        rendered = render_haproxy(config)

        self.assertNotIn("resolvers whatsapp_dns", rendered)
        self.assertIn("server g_whatsapp_net_5222 192.0.2.20:5222\n", rendered)
        self.assertIn("server whatsapp_net_443 192.0.2.21:443\n", rendered)
        self.assertNotIn("server-template", rendered)
        self.assertEqual(rendered.count("balance leastconn"), 2)

    def test_mixed_hostname_and_literal_ip_only_resolves_hostname(self) -> None:
        config = copy.deepcopy(self.config)
        config["probes"]["media_upstream_host"] = "192.0.2.21"

        rendered = render_haproxy(config)

        self.assertIn("resolvers whatsapp_dns", rendered)
        for view, resolver in (
            ("system", "whatsapp_dns_system"),
            ("cloudflare", "whatsapp_dns_cloudflare"),
            ("google", "whatsapp_dns_google"),
        ):
            self.assertIn(
                f"server-template g_whatsapp_net_5222_{view} 4 g.whatsapp.net:5222 "
                f"resolvers {resolver} resolve-prefer ipv4 "
                "resolve-opts prevent-dup-ip init-addr last,none",
                rendered,
            )
        self.assertIn("server whatsapp_net_443 192.0.2.21:443\n", rendered)
        self.assertNotIn("server-template whatsapp_net_443", rendered)
        self.assertEqual(rendered.count("server-template"), 3)


if __name__ == "__main__":
    unittest.main()
