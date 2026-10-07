import unittest

from defensa_azul.splunk_exporter import collector_url


class SplunkExporterTests(unittest.TestCase):
    def test_collector_path_is_added_once(self):
        self.assertEqual(
            "https://splunk.example:8088/services/collector/event",
            collector_url("https://splunk.example:8088"),
        )
        self.assertEqual(
            "https://splunk.example:8088/services/collector/event",
            collector_url("https://splunk.example:8088/services/collector/event"),
        )


if __name__ == "__main__":
    unittest.main()
