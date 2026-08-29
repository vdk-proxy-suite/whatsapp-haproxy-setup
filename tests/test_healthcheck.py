from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
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


def vm_config() -> dict:
    result = config()
    result.update({
        "server": {"public_ip": "192.0.2.100"},
        "ports": {"chat": 443, "media": 587},
    })
    result["probes"].update({
        "timeout_seconds": 2,
        "admin_socket": "/run/haproxy/admin.sock",
    })
    return result


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


def stats_output(*rows: tuple[str, str, str, str]) -> str:
    lines = ["# pxname,svname,status,check_status"]
    lines.extend(",".join(row) for row in rows)
    return "\n".join(lines) + "\n"


def server_state(*rows: tuple[str, str, str, str, str]) -> str:
    lines = ["1", "# be_id be_name srv_id srv_name srv_addr srv_op_state srv_fqdn"]
    for index, (backend, server, address, state, fqdn) in enumerate(rows, 1):
        lines.append(f"{index} {backend} {index} {server} {address} {state} {fqdn}")
    return "\n".join(lines) + "\n"


def hostname_pool_state(
    *,
    chat_fqdn: str = "g.whatsapp.net",
    media_fqdn: str = "whatsapp.net",
    chat_second_address: str = "198.51.100.11",
    chat_second_state: str = "0",
    media_address: str = "198.51.100.20",
    media_state: str = "2",
) -> str:
    return server_state(
        ("whatsapp_chat", "g_whatsapp_net_52221", "198.51.100.10", "2", chat_fqdn),
        (
            "whatsapp_chat",
            "g_whatsapp_net_52222",
            chat_second_address,
            chat_second_state,
            chat_fqdn,
        ),
        ("whatsapp_chat", "g_whatsapp_net_52223", "0.0.0.0", "0", chat_fqdn),
        ("whatsapp_media", "whatsapp_net_4431", media_address, media_state, media_fqdn),
        ("whatsapp_media", "whatsapp_net_4432", "-", "0", media_fqdn),
    )


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


class AdminStatsTests(unittest.TestCase):
    def test_pool_accepts_up_down_and_unassigned_maintenance_slots(self) -> None:
        text = stats_output(
            ("whatsapp_chat", "g_whatsapp_net_52221", "DOWN", "L4TOUT"),
            ("whatsapp_chat", "g_whatsapp_net_52222", "UP", "L4OK"),
            ("whatsapp_chat", "g_whatsapp_net_52223", "MAINT", "Resolution failed"),
            ("whatsapp_media", "whatsapp_net_4431", "UP 1/2", "L4OK"),
            ("whatsapp_media", "whatsapp_net_4432", "MAINT", "INI"),
        )

        result = healthcheck.inspect_admin_stats(config(), text)

        self.assertEqual(result["whatsapp_chat/g_whatsapp_net_52221"]["status"], "DOWN")
        self.assertEqual(result["whatsapp_chat/g_whatsapp_net_52222"]["status"], "UP")
        self.assertEqual(result["whatsapp_chat/g_whatsapp_net_52223"]["status"], "MAINT")
        self.assertEqual(result["whatsapp_media/whatsapp_net_4431"]["status"], "UP 1/2")

    def test_pool_requires_at_least_one_up_slot_per_backend(self) -> None:
        text = stats_output(
            ("whatsapp_chat", "g_whatsapp_net_52221", "DOWN", "L4TOUT"),
            ("whatsapp_chat", "g_whatsapp_net_52222", "MAINT", "INI"),
            ("whatsapp_media", "whatsapp_net_4431", "UP", "L4OK"),
        )

        with self.assertRaisesRegex(RuntimeError, "whatsapp_chat has no UP server.*DOWN.*MAINT"):
            healthcheck.inspect_admin_stats(config(), text)

    def test_hostname_config_requires_template_slot_names(self) -> None:
        legacy = stats_output(
            ("whatsapp_chat", "g_whatsapp_net_5222", "UP", "L4OK"),
            ("whatsapp_media", "whatsapp_net_443", "UP", "L4OK"),
        )

        with self.assertRaisesRegex(RuntimeError, "missing server-template pool"):
            healthcheck.inspect_admin_stats(config(), legacy)

    def test_literal_ipv4_config_requires_static_server_names(self) -> None:
        literal_config = config("192.0.2.10", "192.0.2.20")
        text = stats_output(
            ("whatsapp_chat", "g_whatsapp_net_5222", "UP", "L4OK"),
            ("whatsapp_chat", "g_whatsapp_net_52221", "DOWN", "L4TOUT"),
            ("whatsapp_media", "whatsapp_net_443", "UP", "L4OK"),
        )

        result = healthcheck.inspect_admin_stats(literal_config, text)

        self.assertEqual(
            set(result),
            {"whatsapp_chat/g_whatsapp_net_5222", "whatsapp_media/whatsapp_net_443"},
        )

    def test_admin_stats_keeps_legacy_no_config_call_compatible(self) -> None:
        text = stats_output(
            ("whatsapp_chat", "g_whatsapp_net_5222", "UP", "L4OK"),
            ("whatsapp_media", "whatsapp_net_443", "UP", "L4OK"),
        )

        with patch.object(healthcheck, "admin_command", return_value=text) as admin:
            result = healthcheck.admin_stats("/run/haproxy/admin.sock", 2.0)

        admin.assert_called_once_with("/run/haproxy/admin.sock", "show stat", 2.0)
        self.assertEqual(
            result,
            {
                "whatsapp_chat/g_whatsapp_net_5222": {
                    "status": "UP",
                    "check_status": "L4OK",
                },
                "whatsapp_media/whatsapp_net_443": {
                    "status": "UP",
                    "check_status": "L4OK",
                },
            },
        )


class RuntimeDNSStateTests(unittest.TestCase):
    def test_hostname_pools_report_assigned_down_and_unassigned_slots(self) -> None:
        result = healthcheck.inspect_runtime_dns(
            config(),
            resolver_output(),
            hostname_pool_state(chat_fqdn="G.WHATSAPP.NET."),
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
            result["backends"]["whatsapp_chat"],
            {
                "mode": "dns_pool",
                "server_prefix": "g_whatsapp_net_5222",
                "slots": 3,
                "assigned": 2,
                "up": 1,
                "down": 1,
                "unassigned": 1,
            },
        )
        self.assertEqual(
            result["backends"]["whatsapp_media"],
            {
                "mode": "dns_pool",
                "server_prefix": "whatsapp_net_443",
                "slots": 2,
                "assigned": 1,
                "up": 1,
                "down": 0,
                "unassigned": 1,
            },
        )
        self.assertEqual(result["servers"][0]["fqdn"], "G.WHATSAPP.NET.")
        self.assertFalse(result["servers"][2]["assigned"])
        self.assertIsNone(result["servers"][2]["address"])

    def test_runtime_check_uses_filtered_resolver_and_server_state_commands(self) -> None:
        outputs = {
            "show resolvers whatsapp_dns": resolver_output(),
            "show servers state": hostname_pool_state(),
        }

        with patch.object(
            healthcheck,
            "admin_command",
            side_effect=lambda _path, value, _timeout: outputs[value],
        ) as admin:
            result = healthcheck.runtime_dns_state(config(), "/run/haproxy/admin.sock", 2.0)

        self.assertEqual(len(result["servers"]), 5)
        self.assertEqual(
            admin.call_args_list,
            [
                call("/run/haproxy/admin.sock", "show resolvers whatsapp_dns", 2.0),
                call("/run/haproxy/admin.sock", "show servers state", 2.0),
            ],
        )

    def test_each_unique_hostname_requires_sent_and_valid_activity(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "insufficient activity for 2 hostname upstream"):
            healthcheck.inspect_runtime_dns(
                config(),
                resolver_output(sent=1, valid=1),
                hostname_pool_state(),
            )

        duplicated = config(media_host="g.whatsapp.net")
        result = healthcheck.inspect_runtime_dns(
            duplicated,
            resolver_output(sent=1, valid=1),
            hostname_pool_state(media_fqdn="g.whatsapp.net"),
        )
        self.assertEqual(result["resolver"]["hostname_upstreams"], ["g.whatsapp.net"])

    def test_literal_ipv4_upstreams_remain_static_and_skip_resolver(self) -> None:
        literal_config = config("192.0.2.10", "192.0.2.20")
        literal_state = server_state(
            ("whatsapp_chat", "g_whatsapp_net_5222", "192.0.2.10", "2", "-"),
            ("whatsapp_media", "whatsapp_net_443", "192.0.2.20", "2", "-"),
        )

        with patch.object(healthcheck, "admin_command", return_value=literal_state) as admin:
            result = healthcheck.runtime_dns_state(
                literal_config,
                "/run/haproxy/admin.sock",
                2.0,
            )

        admin.assert_called_once_with("/run/haproxy/admin.sock", "show servers state", 2.0)
        self.assertEqual(result["resolver"]["hostname_upstreams"], [])
        self.assertIn("literal IPv4", result["resolver"]["skipped"])
        self.assertEqual(result["backends"]["whatsapp_chat"]["mode"], "static")
        self.assertEqual(
            [item["address"] for item in result["servers"]],
            ["192.0.2.10", "192.0.2.20"],
        )

    def test_mixed_literal_and_hostname_uses_correct_server_modes(self) -> None:
        mixed_config = config("192.0.2.10", "whatsapp.net")
        mixed_state = server_state(
            ("whatsapp_chat", "g_whatsapp_net_5222", "192.0.2.10", "2", "-"),
            ("whatsapp_media", "whatsapp_net_4431", "198.51.100.20", "2", "whatsapp.net"),
            ("whatsapp_media", "whatsapp_net_4432", "0.0.0.0", "0", "whatsapp.net"),
        )

        result = healthcheck.inspect_runtime_dns(
            mixed_config,
            resolver_output(sent=1, valid=1),
            mixed_state,
        )

        self.assertEqual(result["resolver"]["hostname_upstreams"], ["whatsapp.net"])
        self.assertEqual(result["backends"]["whatsapp_chat"]["mode"], "static")
        self.assertEqual(result["backends"]["whatsapp_media"]["mode"], "dns_pool")

    def test_runtime_state_rejects_wrong_fqdn_and_non_ipv4_address(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "has FQDN.*expected"):
            healthcheck.inspect_runtime_dns(
                config(),
                resolver_output(),
                hostname_pool_state(chat_fqdn="wrong.example"),
            )

        with self.assertRaisesRegex(RuntimeError, "no usable IPv4 address"):
            healthcheck.inspect_runtime_dns(
                config(),
                resolver_output(),
                hostname_pool_state(media_address="2001:db8::20"),
            )

    def test_runtime_state_rejects_duplicate_assigned_ipv4_within_pool(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "assigns duplicate IPv4 address"):
            healthcheck.inspect_runtime_dns(
                config(),
                resolver_output(),
                hostname_pool_state(chat_second_address="198.51.100.10"),
            )

    def test_runtime_state_requires_one_assigned_up_slot_per_backend(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "whatsapp_media has no assigned UP server: assigned=1, slots=2",
        ):
            healthcheck.inspect_runtime_dns(
                config(),
                resolver_output(),
                hostname_pool_state(media_state="0"),
            )

    def test_runtime_hostname_mode_rejects_legacy_single_server(self) -> None:
        legacy_state = server_state(
            ("whatsapp_chat", "g_whatsapp_net_5222", "198.51.100.10", "2", "g.whatsapp.net"),
            ("whatsapp_media", "whatsapp_net_443", "198.51.100.20", "2", "whatsapp.net"),
        )

        with self.assertRaisesRegex(RuntimeError, "missing server-template pool"):
            healthcheck.inspect_runtime_dns(config(), resolver_output(), legacy_state)


class MainVMProbeTests(unittest.TestCase):
    def test_vm_scope_uses_selected_pool_not_generic_upstream_hostname(self) -> None:
        current_config = vm_config()
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["healthcheck.py", "--scope", "vm", "--config", "config.yaml"]),
            patch.object(healthcheck, "load_config", return_value=current_config),
            patch.object(healthcheck, "validate"),
            patch.object(healthcheck, "command", return_value={"returncode": 0}),
            patch.object(healthcheck, "tcp_connect") as direct_tcp,
            patch.object(healthcheck, "tls_connect", return_value={"tls_version": "TLSv1.3"}) as tls,
            patch.object(healthcheck, "admin_stats", return_value={"ok": True}) as stats,
            patch.object(healthcheck, "runtime_dns_state", return_value={"ok": True}) as runtime,
            redirect_stdout(output),
        ):
            return_code = healthcheck.main()

        self.assertEqual(return_code, 0)
        direct_tcp.assert_not_called()
        self.assertEqual(
            [check["name"] for check in json.loads(output.getvalue())["checks"]],
            [
                "haproxy_config",
                "service_active",
                "service_enabled",
                "local_chat_tls",
                "local_media_tls",
                "backend_stats",
                "backend_runtime_dns",
            ],
        )
        self.assertEqual(tls.call_count, 2)
        self.assertEqual(tls.call_args_list[0].args[0], "127.0.0.1")
        self.assertEqual(tls.call_args_list[1].args[0], "127.0.0.1")
        stats.assert_called_once_with("/run/haproxy/admin.sock", 2.0, current_config)
        runtime.assert_called_once_with(current_config, "/run/haproxy/admin.sock", 2.0)


if __name__ == "__main__":
    unittest.main()
