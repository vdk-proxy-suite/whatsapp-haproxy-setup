from __future__ import annotations

import copy
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

    def test_existing_yaml_enables_runtime_dns_without_new_keys(self) -> None:
        self.assertNotIn("dns", self.config)
        validate(self.config)

        rendered = render_haproxy(self.config)

        self.assertIn(
            "resolvers whatsapp_dns\n"
            "    parse-resolv-conf\n"
            "    resolve_retries 3\n"
            "    timeout resolve 5s\n"
            "    timeout retry 1s\n"
            "    hold other 30s\n"
            "    hold refused 30s\n"
            "    hold nx 30s\n"
            "    hold timeout 30s\n"
            "    hold obsolete 15m\n"
            "    accepted_payload_size 4096",
            rendered,
        )
        dns_options = (
            "resolvers whatsapp_dns resolve-prefer ipv4 "
            "resolve-opts prevent-dup-ip init-addr last,none"
        )
        self.assertIn(
            f"server-template g_whatsapp_net_5222 16 g.whatsapp.net:5222 {dns_options}",
            rendered,
        )
        self.assertIn(
            f"server-template whatsapp_net_443 16 whatsapp.net:443 {dns_options}",
            rendered,
        )

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
        self.assertIn(
            "server-template g_whatsapp_net_5222 16 g.whatsapp.net:5222 "
            "resolvers whatsapp_dns resolve-prefer ipv4 "
            "resolve-opts prevent-dup-ip init-addr last,none",
            rendered,
        )
        self.assertIn("server whatsapp_net_443 192.0.2.21:443\n", rendered)
        self.assertNotIn("server-template whatsapp_net_443", rendered)


if __name__ == "__main__":
    unittest.main()
