import unittest

from intelligence import NetworkIntelligenceEngine, SessionReportBuilder
from network_scanner import NetworkInfo


class IntelligenceTests(unittest.TestCase):
    def test_rank_networks_orders_by_score(self):
        engine = NetworkIntelligenceEngine()

        n1 = NetworkInfo(bssid="AA:AA:AA:AA:AA:AA", essid="Legacy", encryption="WEP", signal="-45", clients=12)
        n2 = NetworkInfo(bssid="BB:BB:BB:BB:BB:BB", essid="Modern", encryption="WPA3", signal="-80", clients=1)

        ranked = engine.rank_networks([n2, n1], top_n=2)

        self.assertEqual(ranked[0].bssid, n1.bssid)
        self.assertGreater(ranked[0].score, ranked[1].score)

    def test_report_builder_writes_json(self):
        builder = SessionReportBuilder(output_dir="tests/.tmp_reports")
        network = NetworkInfo(bssid="CC:CC:CC:CC:CC:CC", essid="TestNet", encryption="WPA2", signal="-60", clients=3)

        path = builder.build_report(networks=[network], system_info={"os": "test"}, notes="unit test")

        self.assertTrue(path.endswith('.json'))


if __name__ == "__main__":
    unittest.main()
