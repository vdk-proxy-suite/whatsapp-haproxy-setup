from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SetupRoutePreflightContractTests(unittest.TestCase):
    def test_all_preflights_routes_before_stop_and_backup(self) -> None:
        setup = (ROOT / "setuphaproxy.sh").read_text(encoding="utf-8")
        all_case = setup.split('  all)\n', 1)[1].split('    ;;\n', 1)[0]

        self.assertLess(
            all_case.index('--scope routes'),
            all_case.index('run_step 00'),
        )

    def test_configure_step_rechecks_routes_before_mutating_haproxy_files(self) -> None:
        configure = (ROOT / "steps" / "02-configure.sh").read_text(encoding="utf-8")

        self.assertLess(
            configure.index('--scope routes'),
            configure.index('mkdir -p /etc/haproxy'),
        )


if __name__ == "__main__":
    unittest.main()
