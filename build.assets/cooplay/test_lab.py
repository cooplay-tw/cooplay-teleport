# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
import io
import unittest
from unittest.mock import Mock, MagicMock
from lab_common import Lab, Failure


class ReadinessTests(unittest.TestCase):
    def lab(self, server_exit):
        lab = Lab.__new__(Lab)
        lab._stage = "rollback"
        lab.log = io.BytesIO()
        lab.result = {}
        lab.args = Mock(keep_private_workdir=False)
        lab.teleport = Mock(returncode=server_exit)
        lab.teleport.poll.return_value = server_exit
        denied_probe = Mock(returncode=1)
        denied_probe.poll.return_value = 1
        lab.processes = [denied_probe, lab.teleport]
        lab.http = MagicMock()
        lab.http.open.return_value.__enter__.return_value.status = 200
        return lab

    def test_completed_denial_does_not_fail_restarted_server(self):
        self.lab(None).wait_http("https://example.invalid", 1)

    def test_exited_server_cannot_pass_readiness(self):
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code), self.assertRaises(Failure):
                self.lab(exit_code).wait_http("https://example.invalid", 1)


if __name__ == "__main__":
    unittest.main()
