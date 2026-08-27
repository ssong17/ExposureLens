from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from exposure_lens.config import (
    AppConfig,
    CollectorConfig,
    CompanyConfig,
    validate_config,
)
from exposure_lens.discovery import (
    discover_html,
    discover_robots,
    discover_sitemap,
)
from exposure_lens.pipeline import (
    CollectorPipeline,
    write_run_summary,
)
from exposure_lens.direct_collector import DirectAssetCollector
from exposure_lens.urltools import (
    content_hint,
    host_allowed,
    is_static_asset,
    normalize_url,
    target_platform,
)


class UrlToolsTests(unittest.TestCase):
    def test_normalize_url_removes_tracking_and_fragment(self) -> None:
        actual = normalize_url("HTTPS://Example.COM:443/a?utm_source=x&b=2#part")
        self.assertEqual(actual, "https://example.com/a?b=2")

    def test_subdomain_allowlist(self) -> None:
        self.assertTrue(host_allowed("https://docs.example.com/a", ("example.com",)))
        self.assertFalse(
            host_allowed("https://example.com.attacker.test/a", ("example.com",))
        )

    def test_content_and_platform_hints(self) -> None:
        self.assertEqual(content_hint("https://cdn.test/a/report.PDF"), "pdf")
        self.assertEqual(
            target_platform("https://github.com/acme/repo", ("acme.test",)),
            "github",
        )

    def test_static_assets_are_classified_by_extension(self) -> None:
        self.assertTrue(is_static_asset("https://cdn.test/logo.png"))
        self.assertTrue(is_static_asset("https://cdn.test/site.css"))
        self.assertFalse(is_static_asset("https://cdn.test/app.js"))
        self.assertFalse(is_static_asset("https://api.test/users"))


class DiscoveryTests(unittest.TestCase):
    def test_html_links(self) -> None:
        links = discover_html(
            "https://example.com/resources/",
            b'<a href="guide.pdf">Guide</a><script src="/app.js"></script>',
        )
        self.assertEqual(
            [item.target_url for item in links],
            [
                "https://example.com/resources/guide.pdf",
                "https://example.com/app.js",
            ],
        )

    def test_sitemap(self) -> None:
        links = discover_sitemap(
            "https://example.com/sitemap.xml",
            (
                b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                b"<url><loc>https://example.com/a</loc></url></urlset>"
            ),
        )
        self.assertEqual(links[0].target_url, "https://example.com/a")
        self.assertEqual(links[0].discovery_method, "sitemap")

    def test_robots_sitemap(self) -> None:
        links = discover_robots(
            "https://example.com/robots.txt",
            b"User-agent: *\nSitemap: https://example.com/site.xml\n",
        )
        self.assertEqual(links[0].target_url, "https://example.com/site.xml")


class ConfigTests(unittest.TestCase):
    def make_collector(self) -> CollectorConfig:
        return CollectorConfig(
            user_agent="test",
            request_interval_seconds=1,
            timeout_seconds=5,
            max_retries=1,
            max_depth=1,
            max_requests=10,
            max_response_bytes=1000,
            respect_robots=True,
            fetch_query_urls=False,
        )

    def test_external_fetch_domain_is_rejected(self) -> None:
        app = AppConfig(
            collector=self.make_collector(),
            companies=(
                CompanyConfig(
                    company_id="acme",
                    company_code="ACME",
                    groups=("test",),
                    enabled=True,
                    name="Acme",
                    indicator="Acme domain",
                    allowed_domains=("acme.test",),
                    fetch_domains=("cdn.other.test",),
                    seed_urls=("https://acme.test/",),
                    ownership_evidence_urls=("https://acme.test/about",),
                    security_contact="security@acme.test",
                ),
            ),
        )
        with self.assertRaises(ValueError):
            validate_config(app)

    def test_seed_must_be_fetch_allowed(self) -> None:
        app = AppConfig(
            collector=self.make_collector(),
            companies=(
                CompanyConfig(
                    company_id="acme",
                    company_code="ACME",
                    groups=("test",),
                    enabled=True,
                    name="Acme",
                    indicator="Acme domain",
                    allowed_domains=("acme.test", "other.test"),
                    fetch_domains=("acme.test",),
                    seed_urls=("https://other.test/",),
                    ownership_evidence_urls=("https://acme.test/about",),
                    security_contact="security@acme.test",
                ),
            ),
        )
        with self.assertRaises(ValueError):
            validate_config(app)

    def test_group_selects_only_enabled_members(self) -> None:
        enabled = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )
        disabled = CompanyConfig(
            company_id="other",
            company_code="OTHER",
            groups=("pilot",),
            enabled=False,
            name="Other",
            indicator="Other domain",
            allowed_domains=("other.test",),
            fetch_domains=("other.test",),
            seed_urls=("https://other.test/",),
            ownership_evidence_urls=(),
            security_contact="",
        )
        app = AppConfig(self.make_collector(), (enabled, disabled))
        self.assertEqual(app.get_group("pilot"), (enabled,))

    def test_candidate_id_contains_company_code_and_date(self) -> None:
        company = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )
        pipeline = CollectorPipeline(
            AppConfig(self.make_collector(), (company,)),
            company,
        )
        pipeline._add_candidate(
            "https://acme.test/",
            "https://acme.test/a",
            "seed",
            "html",
        )
        candidate = pipeline._candidates[0]
        self.assertRegex(candidate.candidate_id, r"^DIR_ACME_\d{8}_000001$")

    def test_static_asset_is_separated_from_analysis_candidates(self) -> None:
        company = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )
        pipeline = CollectorPipeline(
            AppConfig(self.make_collector(), (company,)),
            company,
        )

        pipeline._add_candidate(
            "https://acme.test/",
            "https://acme.test/logo.png",
            "html_link",
            "png",
        )

        self.assertEqual(pipeline._candidates, [])
        self.assertEqual(pipeline.static_assets[0].content_hint, "png")


class OutputTests(unittest.TestCase):
    def test_run_summary_lists_target_companies(self) -> None:
        company = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "summary.md"
            write_run_summary(
                (company,),
                summary_path,
                {
                    "acme": {
                        "candidate_count": 3,
                        "index_request_count": 2,
                        "search_queries": ("site:acme.test api",),
                        "errors": (),
                    }
                },
            )
            content = summary_path.read_text(encoding="utf-8")

        self.assertIn("Acme (`acme`)", content)
        self.assertIn("acme.jsonl", content)
        self.assertIn("트랙: `DIRECT`", content)
        self.assertIn("site:acme.test api", content)

    def test_passive_collector_keeps_only_official_domain_urls(self) -> None:
        company = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )
        app = AppConfig(ConfigTests().make_collector(), (company,))
        collector = DirectAssetCollector(app, company, fetch_json=lambda _: [])

        collector._add_candidate(
            "https://index.test/",
            "https://api.acme.test/openapi.json?key=visible",
            "test_index",
        )
        collector._add_candidate(
            "https://index.test/",
            "https://attacker.test/openapi.json",
            "test_index",
        )

        self.assertEqual(len(collector._candidates), 1)
        self.assertEqual(collector._candidates[0].track, "DIRECT")
        self.assertRegex(
            collector._candidates[0].candidate_id,
            r"^DIR_ACME_\d{8}_000001$",
        )
        self.assertIn("key=visible", collector._candidates[0].target_url)

    def test_passive_collection_includes_configured_seed(self) -> None:
        company = CompanyConfig(
            company_id="acme",
            company_code="ACME",
            groups=("pilot",),
            enabled=True,
            name="Acme",
            indicator="Acme domain",
            allowed_domains=("acme.test",),
            fetch_domains=("acme.test",),
            seed_urls=("https://acme.test/docs?version=1",),
            ownership_evidence_urls=("https://acme.test/about",),
            security_contact="security@acme.test",
        )
        app = AppConfig(ConfigTests().make_collector(), (company,))
        collector = DirectAssetCollector(app, company, fetch_json=lambda _: [])

        candidates = collector.collect()

        self.assertEqual(candidates[0].target_url, "https://acme.test/docs?version=1")
        self.assertEqual(candidates[0].discovery_method, "official_domain_config")


if __name__ == "__main__":
    unittest.main()
