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

    def test_shared_443_is_opt_in_and_keeps_raw_587_fallback(self) -> None:
        config = copy.deepcopy(self.config)
        config["shared_443"] = {
            "enabled": True,
            "chat_loopback_port": 18443,
            "probe_sni": "media-hel3-1.cdn.whatsapp.net",
            "media_sni": {
                "exact": ["whatsapp.net", "mmg.whatsapp.net"],
                "suffixes": [".cdn.whatsapp.net"],
            },
        }

        rendered = render_haproxy(config)
        shared_frontend = section(rendered, "frontend whatsapp_shared_443")
        chat_frontend = section(rendered, "frontend whatsapp_chat_tls")
        loop_backend = section(rendered, "backend whatsapp_chat_tls_loop")
        media_frontend = section(rendered, "frontend whatsapp_media")
        chat_backend = section(rendered, "backend whatsapp_chat")
        media_backend = section(rendered, "backend whatsapp_media")
        capacity_table = section(rendered, "backend public_capacity_table")

        self.assertIn("tune.bufsize 16384", rendered)
        self.assertIn("    maxconn 96", rendered)
        self.assertIn("    maxconnrate 45", rendered)
        self.assertIn(
            "stick-table type string len 16 size 1 expire 10m "
            "store conn_cur,conn_rate(1s)",
            capacity_table,
        )
        self.assertIn("bind 0.0.0.0:443", shared_frontend)
        self.assertNotIn(" ssl ", shared_frontend)
        self.assertIn("maxconn 48", shared_frontend)
        self.assertIn("tcp-request connection track-sc0", shared_frontend)
        self.assertIn(
            "tcp-request connection track-sc1 str(public) "
            "table public_capacity_table",
            shared_frontend,
        )
        self.assertIn("sc1_conn_cur gt 64", shared_frontend)
        self.assertIn("sc1_conn_rate gt 30", shared_frontend)
        self.assertIn("tcp-request connection set-dst", shared_frontend)
        self.assertIn(
            "acl shared_443_media_exact req.ssl_sni,lower -m str "
            "whatsapp.net mmg.whatsapp.net",
            shared_frontend,
        )
        self.assertIn(
            "acl shared_443_media_suffix req.ssl_sni,lower -m end .cdn.whatsapp.net",
            shared_frontend,
        )
        self.assertIn("tcp-request content capture req.ssl_sni len 128", shared_frontend)
        self.assertLess(
            shared_frontend.index("tcp-request content capture req.ssl_sni"),
            shared_frontend.index("tcp-request content accept if shared_443_hello"),
        )
        self.assertIn("tcp-request content reject if WAIT_END", shared_frontend)
        self.assertNotIn("tcp-request content accept if WAIT_END", shared_frontend)
        self.assertIn(
            "use_backend whatsapp_media if shared_443_hello "
            "shared_443_media_exact",
            shared_frontend,
        )
        self.assertIn(
            "use_backend whatsapp_media if shared_443_hello "
            "shared_443_media_suffix",
            shared_frontend,
        )
        self.assertIn("default_backend whatsapp_chat_tls_loop", shared_frontend)
        self.assertIn("server chat_tls 127.0.0.1:18443 send-proxy", loop_backend)
        self.assertNotIn("check", loop_backend)
        self.assertIn(
            "bind 127.0.0.1:18443 accept-proxy ssl crt "
            "/etc/haproxy/ssl/proxy.whatsapp.net.pem",
            chat_frontend,
        )
        self.assertNotIn("req.ssl_sni", chat_frontend)
        self.assertNotIn("track-sc0", chat_frontend)
        self.assertNotIn("set-dst", chat_frontend)
        self.assertIn("default_backend whatsapp_chat", chat_frontend)
        self.assertEqual(rendered.count("tcp-request connection track-sc0"), 2)
        self.assertEqual(rendered.count("tcp-request connection track-sc1"), 2)
        self.assertIn("bind 0.0.0.0:587", media_frontend)
        self.assertIn("track-sc1 str(public)", media_frontend)
        self.assertIn("observe layer4 send-proxy", chat_backend)
        self.assertNotIn("send-proxy", media_backend)

    def test_disabled_shared_443_keeps_legacy_render(self) -> None:
        legacy = render_haproxy(self.config)
        config = copy.deepcopy(self.config)
        config["shared_443"] = {"enabled": False}

        self.assertEqual(render_haproxy(config), legacy)

    def test_shared_443_rejects_disallowed_cidrs_before_tracking(self) -> None:
        config = copy.deepcopy(self.config)
        config["access"]["allowed_cidrs"] = ["198.51.100.0/24"]
        config["shared_443"] = {
            "enabled": True,
            "chat_loopback_port": 18443,
            "probe_sni": "media-hel3-1.cdn.whatsapp.net",
            "media_sni": {
                "exact": ["whatsapp.net", "mmg.whatsapp.net"],
                "suffixes": [".cdn.whatsapp.net"],
            },
        }

        shared_frontend = section(
            render_haproxy(config),
            "frontend whatsapp_shared_443",
        )
        self.assertLess(
            shared_frontend.index("reject if !allowed_client"),
            shared_frontend.index("track-sc0"),
        )
        self.assertLess(
            shared_frontend.index("track-sc0"),
            shared_frontend.index("track-sc1"),
        )
        self.assertLess(
            shared_frontend.index("track-sc1"),
            shared_frontend.index("reject if { sc0_conn_cur"),
        )

    def test_shared_443_schema_is_strict_and_fail_safe(self) -> None:
        valid_shared = {
            "enabled": True,
            "chat_loopback_port": 18443,
            "probe_sni": "media-hel3-1.cdn.whatsapp.net",
            "media_sni": {
                "exact": ["whatsapp.net", "mmg.whatsapp.net"],
                "suffixes": [".cdn.whatsapp.net"],
            },
        }
        valid = copy.deepcopy(self.config)
        valid["shared_443"] = valid_shared
        validate(valid)

        invalid_shared_values = (
            None,
            [],
            {},
            {"enabled": False, "chat_loopback_port": 18443},
            {"enabled": True},
            {
                "enabled": True,
                "chat_loopback_port": 443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": valid_shared["media_sni"],
            },
            {
                "enabled": True,
                "chat_loopback_port": 18443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": {"exact": [], "suffixes": []},
            },
            {
                "enabled": True,
                "chat_loopback_port": 18443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": {
                    "exact": ["whatsapp.net"],
                    "suffixes": ["*.whatsapp.net"],
                },
            },
            {
                "enabled": True,
                "chat_loopback_port": 18443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": {
                    "exact": ["whatsapp.net"],
                    "suffixes": [".whatsapp.net"],
                },
            },
            {
                "enabled": True,
                "chat_loopback_port": 18443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": {
                    "exact": ["mmg.whatsapp.net"],
                    "suffixes": [".cdn.whatsapp.net"],
                },
            },
            {
                "enabled": True,
                "chat_loopback_port": 18443,
                "probe_sni": valid_shared["probe_sni"],
                "media_sni": {
                    "exact": ["whatsapp.net", "WHATSAPP.NET"],
                    "suffixes": [".cdn.whatsapp.net"],
                },
            },
            {**valid_shared, "probe_sni": "example.com"},
            {**valid_shared, "unknown": True},
        )
        for shared in invalid_shared_values:
            with self.subTest(shared=shared):
                config = copy.deepcopy(self.config)
                config["shared_443"] = shared
                with self.assertRaises(ValueError):
                    validate(config)

        wrong_chat_port = copy.deepcopy(valid)
        wrong_chat_port["ports"]["chat"] = 8443
        with self.assertRaisesRegex(ValueError, "ports.chat to be exactly 443"):
            validate(wrong_chat_port)

        route_collision = copy.deepcopy(valid)
        route_collision["routes"] = {
            "media": {
                "mode": "socks4",
                "socks4": {"host": "127.0.0.1", "port": 18443},
            },
        }
        with self.assertRaisesRegex(ValueError, "differ from local SOCKS4 route ports"):
            validate(route_collision)

        certificate_collision = copy.deepcopy(valid)
        certificate_collision["certificate"]["dns_names"] = ["mmg.whatsapp.net"]
        with self.assertRaisesRegex(ValueError, r"certificate\.dns_names\[0\]"):
            validate(certificate_collision)

        wildcard_certificate_collision = copy.deepcopy(valid)
        wildcard_certificate_collision["certificate"]["dns_names"] = [
            "*.cdn.whatsapp.net"
        ]
        with self.assertRaisesRegex(ValueError, r"certificate\.dns_names\[0\]"):
            validate(wildcard_certificate_collision)

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
