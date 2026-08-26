from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import call, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import healthcheck  # noqa: E402


def config(chat_host: str = "g.whatsapp.net", media_host: str = "whatsapp.net") -> dict:
    return {
        "probes": {
            "chat_upstream_host": chat_host,
            "media_upstream_host": media_host,
        }
    }


def resolver_output(sent: int = 8, valid: int = 4, update: int = 2) -> str:
    return f"""Resolvers section whatsapp_dns
  nameserver 127.0.0.53:
    sent:        {sent}
    snd_error:   0
    valid:       {valid}
    update:      {update}
    cname:       1
    cname_error: 0
    nx:          0
    timeout:     0
"""


def server_state(
    chat_addr: str = "198.51.100.10",
    chat_fqdn: str = "g.whatsapp.net",
    media_addr: str = "198.51.100.20",
    media_fqdn: str = "whatsapp.net",
) -> str:
    return f"""1
# be_id be_name srv_id srv_name srv_addr srv_op_state srv_fqdn
1 whatsapp_chat 1 g_whatsapp_net_5222 {chat_addr} 2 {chat_fqdn}
2 whatsapp_media 1 whatsapp_net_443 {media_addr} 2 {media_fqdn}
"""


class ResolverParsingTests(unittest.TestCase):
    def test_resolver_stats_aggregate_all_nameservers(self) -> None:
        text = """Resolvers section whatsapp_dns
  nameserver dns-a:
    sent: 5
    valid: 2
    update: 1
  nameserver dns-b:
    sent: 7
    valid: 3
    update: 2
"""

        self.assertEqual(
            healthcheck.parse_resolver_stats(text),
            {
                "section": "whatsapp_dns",
                "nameserver_count": 2,
                "sent": 12,
                "valid": 5,
                "update": 3,
            },
        )

    def test_resolver_stats_require_sent_and_valid_counters(self) -> None:
        text = """Resolvers section whatsapp_dns
  nameserver dns-a:
    sent: 5
"""

        with self.assertRaisesRegex(RuntimeError, "counters are incomplete"):
            healthcheck.parse_resolver_stats(text)


class ExistingAdminStatsTests(unittest.TestCase):
    def test_backend_up_check_uses_reusable_admin_command(self) -> None:
        text = """# pxname,svname,status,check_status
whatsapp_chat,g_whatsapp_net_5222,UP,L4OK
whatsapp_media,whatsapp_net_443,UP,L4OK
"""

        with patch.object(healthcheck, "admin_command", return_value=text) as admin:
            result = healthcheck.admin_stats("/run/haproxy/admin.sock", 2.0)

        admin.assert_called_once_with("/run/haproxy/admin.sock", "show stat", 2.0)
        self.assertEqual(
            result,
            {
                "whatsapp_chat/g_whatsapp_net_5222": {"status": "UP", "check_status": "L4OK"},
                "whatsapp_media/whatsapp_net_443": {"status": "UP", "check_status": "L4OK"},
            },
        )


class RuntimeDNSStateTests(unittest.TestCase):
    def test_hostname_upstreams_report_exact_runtime_fqdn_and_ipv4(self) -> None:
        result = healthcheck.inspect_runtime_dns(
            config(),
            resolver_output(),
            server_state(chat_fqdn="G.WHATSAPP.NET."),
        )

        self.assertEqual(result["server_state_version"], 1)
        self.assertEqual(
            result["resolver"],
            {
                "section": "whatsapp_dns",
                "nameserver_count": 1,
                "sent": 8,
                "valid": 4,
                "update": 2,
                "hostname_upstreams": ["g.whatsapp.net", "whatsapp.net"],
            },
        )
        self.assertEqual(
            result["servers"],
            [
                {
                    "backend": "whatsapp_chat",
                    "server": "g_whatsapp_net_5222",
                    "configured_host": "g.whatsapp.net",
                    "fqdn": "G.WHATSAPP.NET.",
                    "address": "198.51.100.10",
                    "operational_state": "2",
                },
                {
                    "backend": "whatsapp_media",
                    "server": "whatsapp_net_443",
                    "configured_host": "whatsapp.net",
                    "fqdn": "whatsapp.net",
                    "address": "198.51.100.20",
                    "operational_state": "2",
                },
            ],
        )

    def test_runtime_check_uses_filtered_resolver_and_server_state_commands(self) -> None:
        outputs = {
            "show resolvers whatsapp_dns": resolver_output(),
            "show servers state": server_state(),
        }

        with patch.object(healthcheck, "admin_command", side_effect=lambda _path, value, _timeout: outputs[value]) as admin:
            result = healthcheck.runtime_dns_state(config(), "/run/haproxy/admin.sock", 2.0)

        self.assertEqual(len(result["servers"]), 2)
        self.assertEqual(
            admin.call_args_list,
            [
                call("/run/haproxy/admin.sock", "show resolvers whatsapp_dns", 2.0),
                call("/run/haproxy/admin.sock", "show servers state", 2.0),
            ],
        )

    def test_each_unique_hostname_requires_sent_and_valid_activity(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "insufficient activity for 2 hostname upstream"):
            healthcheck.inspect_runtime_dns(config(), resolver_output(sent=1, valid=1), server_state())

        duplicated = config(media_host="g.whatsapp.net")
        duplicated_state = server_state(media_fqdn="g.whatsapp.net")
        result = healthcheck.inspect_runtime_dns(
            duplicated,
            resolver_output(sent=1, valid=1),
            duplicated_state,
        )
        self.assertEqual(result["resolver"]["hostname_upstreams"], ["g.whatsapp.net"])

    def test_literal_ipv4_upstreams_skip_resolver_counters(self) -> None:
        literal_config = config("192.0.2.10", "192.0.2.20")
        literal_state = server_state(
            chat_addr="192.0.2.10",
            chat_fqdn="-",
            media_addr="192.0.2.20",
            media_fqdn="-",
        )

        with patch.object(healthcheck, "admin_command", return_value=literal_state) as admin:
            result = healthcheck.runtime_dns_state(literal_config, "/run/haproxy/admin.sock", 2.0)

        admin.assert_called_once_with("/run/haproxy/admin.sock", "show servers state", 2.0)
        self.assertEqual(result["resolver"]["hostname_upstreams"], [])
        self.assertIn("literal IPv4", result["resolver"]["skipped"])
        self.assertEqual(
            [item["address"] for item in result["servers"]],
            ["192.0.2.10", "192.0.2.20"],
        )

    def test_mixed_literal_and_hostname_requires_only_hostname_dns_activity(self) -> None:
        mixed_config = config("192.0.2.10", "whatsapp.net")
        mixed_state = server_state(chat_addr="192.0.2.10", chat_fqdn="-")

        result = healthcheck.inspect_runtime_dns(
            mixed_config,
            resolver_output(sent=1, valid=1),
            mixed_state,
        )

        self.assertEqual(result["resolver"]["hostname_upstreams"], ["whatsapp.net"])
        self.assertEqual(result["servers"][0]["fqdn"], None)
        self.assertEqual(result["servers"][1]["fqdn"], "whatsapp.net")

    def test_runtime_state_rejects_wrong_fqdn_and_non_ipv4_address(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "has FQDN.*expected"):
            healthcheck.inspect_runtime_dns(
                config(), resolver_output(), server_state(chat_fqdn="wrong.example"),
            )

        with self.assertRaisesRegex(RuntimeError, "no usable IPv4 address"):
            healthcheck.inspect_runtime_dns(
                config(), resolver_output(), server_state(media_addr="2001:db8::20"),
            )


if __name__ == "__main__":
    unittest.main()
