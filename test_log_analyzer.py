import unittest

from log_analyzer import count_failed_attempts


class TestCountFailedAttempts(unittest.TestCase):
    def test_sample_scenario_counts(self):
        lines = [
            "Jan 10 10:00:01 server sshd[1001]: Failed password for root from 203.0.113.5 port 51514 ssh2",
            "Jan 10 10:00:05 server sshd[1002]: Failed password for root from 203.0.113.5 port 51515 ssh2",
            "Jan 10 10:00:09 server sshd[1003]: Invalid user admin from 203.0.113.5 port 51516",
            "Jan 10 10:00:09 server sshd[1003]: Failed password for invalid user admin from 203.0.113.5 port 51516 ssh2",
            "Jan 10 10:00:12 server sshd[1004]: Failed password for root from 203.0.113.5 port 51517 ssh2",
            "Jan 10 10:00:15 server sshd[1005]: Failed password for root from 203.0.113.5 port 51518 ssh2",
            "Jan 10 10:00:20 server sshd[1006]: Failed password for root from 203.0.113.5 port 51519 ssh2",
            "Jan 10 10:01:00 server sshd[1007]: Invalid user test from 198.51.100.9 port 22",
            "Jan 10 10:01:00 server sshd[1007]: Failed password for invalid user test from 198.51.100.9 port 22 ssh2",
            "Jan 10 10:05:00 server sshd[1009]: Accepted password for enes from 192.0.2.44 port 60000 ssh2",
            "Jan 10 10:06:00 server sshd[1010]: Failed password for guest from 192.0.2.44 port 60001 ssh2",
            "Jan 10 10:07:00 server sshd[1011]: Failed password for a from 9.9.9.9 port 1 from 6.6.6.6 port 2222 ssh2",
            "Jan 10 10:08:00 server sshd[1012]: Failed password for baduser from 999.999.999.999 port 22 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(
            counts,
            {
                "203.0.113.5": 6,
                "198.51.100.9": 1,
                "192.0.2.44": 1,
                "6.6.6.6": 1,
            },
        )

    def test_log_injection_fake_ip_not_counted(self):
        lines = [
            "Failed password for a from 9.9.9.9 port 1 from 6.6.6.6 port 2222 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertNotIn("9.9.9.9", counts)
        self.assertEqual(counts["6.6.6.6"], 1)

    def test_invalid_ip_octet_not_counted(self):
        lines = [
            "Failed password for baduser from 999.999.999.999 port 22 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(counts, {})

    def test_invalid_user_line_not_double_counted(self):
        lines = [
            "Invalid user admin from 203.0.113.5 port 51516",
            "Failed password for invalid user admin from 203.0.113.5 port 51516 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(counts["203.0.113.5"], 1)

    def test_accepted_password_not_counted(self):
        lines = [
            "Accepted password for enes from 192.0.2.44 port 60000 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(counts, {})


if __name__ == "__main__":
    unittest.main()
