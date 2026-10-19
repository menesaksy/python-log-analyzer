import unittest

from log_analyzer import analyze, count_failed_attempts


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
            "Jan 10 10:07:00 server sshd[1011]: Failed password for a from 9.9.9.9 port 1 from 6.6.6.6 port 2222 ssh2",
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
            "Jan 10 10:00:09 server sshd[1003]: Invalid user admin from 203.0.113.5 port 51516",
            "Jan 10 10:00:09 server sshd[1003]: Failed password for invalid user admin from 203.0.113.5 port 51516 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(counts["203.0.113.5"], 1)

    def test_accepted_password_not_counted(self):
        lines = [
            "Accepted password for enes from 192.0.2.44 port 60000 ssh2",
        ]

        counts = count_failed_attempts(lines)

        self.assertEqual(counts, {})


class TestAnalyze(unittest.TestCase):
    def test_breach_detected_when_success_follows_threshold_failures(self):
        lines = [
            "Jan 10 10:00:01 server sshd[2001]: Failed password for root from 10.1.1.1 port 1 ssh2",
            "Jan 10 10:00:02 server sshd[2002]: Failed password for root from 10.1.1.1 port 2 ssh2",
            "Jan 10 10:00:03 server sshd[2003]: Failed password for root from 10.1.1.1 port 3 ssh2",
            "Jan 10 10:00:04 server sshd[2004]: Accepted password for root from 10.1.1.1 port 4 ssh2",
        ]

        counts, breached = analyze(lines, threshold=3)

        self.assertEqual(counts["10.1.1.1"], 3)
        self.assertIn("10.1.1.1", breached)

    def test_no_breach_when_failures_below_threshold(self):
        lines = [
            "Jan 10 10:00:01 server sshd[2001]: Failed password for root from 10.1.1.2 port 1 ssh2",
            "Jan 10 10:00:02 server sshd[2002]: Failed password for root from 10.1.1.2 port 2 ssh2",
            "Jan 10 10:00:03 server sshd[2003]: Accepted password for root from 10.1.1.2 port 3 ssh2",
        ]

        counts, breached = analyze(lines, threshold=3)

        self.assertNotIn("10.1.1.2", breached)

    def test_no_breach_when_success_comes_before_failures(self):
        lines = [
            "Jan 10 10:00:01 server sshd[2001]: Accepted password for root from 10.1.1.3 port 1 ssh2",
            "Jan 10 10:00:02 server sshd[2002]: Failed password for root from 10.1.1.3 port 2 ssh2",
            "Jan 10 10:00:03 server sshd[2003]: Failed password for root from 10.1.1.3 port 3 ssh2",
            "Jan 10 10:00:04 server sshd[2004]: Failed password for root from 10.1.1.3 port 4 ssh2",
        ]

        counts, breached = analyze(lines, threshold=3)

        self.assertNotIn("10.1.1.3", breached)

    def test_breach_isolated_per_ip(self):
        lines = [
            "Jan 10 10:00:01 server sshd[2001]: Failed password for root from 10.1.1.4 port 1 ssh2",
            "Jan 10 10:00:02 server sshd[2002]: Failed password for root from 10.1.1.4 port 2 ssh2",
            "Jan 10 10:00:03 server sshd[2003]: Failed password for root from 10.1.1.4 port 3 ssh2",
            "Jan 10 10:00:04 server sshd[2004]: Accepted password for root from 10.1.1.5 port 4 ssh2",
        ]

        counts, breached = analyze(lines, threshold=3)

        self.assertEqual(breached, set())

    def test_fake_accepted_in_username_not_treated_as_breach(self):
        lines = [
            "Jan 10 10:06:00 server sshd[1010]: Failed password for guest from 6.6.6.6 port 2221 ssh2",
            "Jan 10 10:07:00 server sshd[1011]: Failed password for Accepted password for x "
            "from 1.2.3.4 port 1 ssh2 from 6.6.6.6 port 2222 ssh2",
        ]

        counts, breached = analyze(lines, threshold=1)

        self.assertEqual(counts["6.6.6.6"], 2)
        self.assertNotIn("6.6.6.6", breached)
        self.assertNotIn("1.2.3.4", counts)
        self.assertNotIn("1.2.3.4", breached)


    def test_nested_forged_prefix_in_username_not_treated_as_breach(self):
        lines = [
            "Jan 10 10:10:00 server sshd[1019]: Failed password for guest from 8.8.8.8 port 1 ssh2",
            "Jan 10 10:10:05 server sshd[1020]: Failed password for x sshd[1]: Accepted password for y "
            "from 7.7.7.7 port 1 ssh2 from 8.8.8.8 port 2 ssh2",
        ]

        counts, breached = analyze(lines, threshold=1)

        self.assertEqual(counts["8.8.8.8"], 2)
        self.assertNotIn("8.8.8.8", breached)
        self.assertNotIn("7.7.7.7", counts)
        self.assertNotIn("7.7.7.7", breached)


if __name__ == "__main__":
    unittest.main()
