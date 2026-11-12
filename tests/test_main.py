import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main


class WhoIsClassificationTests(unittest.TestCase):
    @patch("main.whois.whois")
    def test_registered_domain(self, whois_mock):
        whois_mock.return_value = SimpleNamespace(domain_name="example.com")

        result = main.checkDomainRegistration("example.com")

        self.assertEqual(result.status, main.STATUS_REGISTERED)

    @patch("main.whois.whois")
    def test_unregistered_domain(self, whois_mock):
        whois_mock.return_value = SimpleNamespace(
            domain_name=None,
            text='No match for "missing.example".',
        )

        result = main.checkDomainRegistration("missing.example")

        self.assertEqual(result.status, main.STATUS_UNREGISTERED)

    @patch("main.whois.whois")
    def test_timeout_is_unknown(self, whois_mock):
        whois_mock.return_value = SimpleNamespace(
            domain_name=None,
            text="Socket not responding: timed out",
        )

        result = main.checkDomainRegistration("example.com")

        self.assertEqual(result.status, main.STATUS_UNKNOWN)

    @patch("main.whois.whois")
    def test_empty_response_is_unknown(self, whois_mock):
        whois_mock.return_value = SimpleNamespace(domain_name=None, text="")

        result = main.checkDomainRegistration("example.com")

        self.assertEqual(result.status, main.STATUS_UNKNOWN)

    @patch("main.whois.whois")
    def test_no_match_exception_is_unregistered(self, whois_mock):
        whois_mock.side_effect = Exception('No match for "missing.example".')

        result = main.checkDomainRegistration("missing.example")

        self.assertEqual(result.status, main.STATUS_UNREGISTERED)

    @patch("main.whois.whois")
    def test_other_exception_is_error(self, whois_mock):
        whois_mock.side_effect = RuntimeError("unexpected parser failure")

        result = main.checkDomainRegistration("example.com")

        self.assertEqual(result.status, main.STATUS_ERROR)


class ResponseLimitTests(unittest.TestCase):
    def test_read_response_text_stops_at_limit(self):
        response = SimpleNamespace(
            headers={},
            encoding="utf-8",
            iter_content=lambda chunk_size: iter((b"abc", b"def")),
        )

        text, truncated = main.read_response_text(response, 4)

        self.assertEqual(text, "abcd")
        self.assertTrue(truncated)


class ScanPageTests(unittest.TestCase):
    def _http_client(self):
        return SimpleNamespace(
            fetch_text=lambda url: main.FetchResult(
                requested_url=url,
                final_url=url,
                status_code=200,
                text='<script src="https://unknown-test.com/app.js"></script>',
            )
        )

    def test_single_page_scan_returns_findings_without_global_state(self):
        page_url = "https://source.example/page"
        http_client = SimpleNamespace(
            fetch_text=lambda url: main.FetchResult(
                requested_url=url,
                final_url=url,
                status_code=200,
                text=(
                    '<script src="https://missing-test.com/app.js"></script>'
                    '<script src="https://cdn-test.com/app.js"></script>'
                ),
            )
        )
        config = main.ScanConfig(threads=2)

        with patch(
            "main.checkDomainRegistration",
            side_effect=lambda domain: main.DomainCheckResult(
                domain=domain,
                status=(
                    main.STATUS_UNREGISTERED
                    if domain == "missing-test.com"
                    else main.STATUS_REGISTERED
                ),
            ),
        ), patch(
            "main.checkBucketNotFound",
            side_effect=lambda url, client: main.BucketCheckResult(
                url=url,
                broken=False,
            ),
        ):
            result = main.scan_page(page_url, config, http_client)

        self.assertEqual(
            result.extracted_urls,
            ["https://cdn-test.com", "https://missing-test.com"],
        )
        self.assertEqual(
            [(finding.kind, finding.target) for finding in result.findings],
            [("domain", "missing-test.com")],
        )

    def test_unknown_whois_status_does_not_create_finding(self):
        config = main.ScanConfig(threads=2)

        with patch(
            "main.checkDomainRegistration",
            return_value=main.DomainCheckResult(
                domain="unknown-test.com",
                status=main.STATUS_UNKNOWN,
            ),
        ), patch(
            "main.checkBucketNotFound",
            return_value=main.BucketCheckResult(
                url="https://unknown-test.com",
                broken=False,
            ),
        ):
            result = main.scan_page(
                "https://source.example/page",
                config,
                self._http_client(),
            )

        self.assertEqual(result.findings, [])


class JsonOutputTests(unittest.TestCase):
    def test_json_uses_english_keys_and_removes_unused_fields(self):
        finding = main.Finding(
            kind="domain",
            source_url="https://source.example/page",
            target="missing-test.com",
        )

        result = main.genVulnJson("https://source.example/page", [finding])

        self.assertEqual(
            set(result),
            {
                "name",
                "severity",
                "url",
                "description",
                "impact",
                "recommendation",
            },
        )


if __name__ == "__main__":
    unittest.main()
