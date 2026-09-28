from __future__ import annotations

from exposure_lens.sources import urlscan


def test_observations_carry_recency():
    class H:
        def get_json(self, url):
            return {"results": [
                {"page": {"url": "https://a.x.com/p", "status": 200},
                 "task": {"time": "2026-09-01T12:00:00.000Z", "url": "https://a.x.com/t"}},
            ]}

    obs = urlscan.fetch_observations(H(), "x.com")
    assert any(o["seen"] == "2026-09-01" for o in obs)
    assert any(o["status"] == "200" for o in obs)


def test_paginates_beyond_one_page():
    class H:
        def __init__(self):
            self.calls = []

        def get_json(self, url):
            self.calls.append(url)
            page = len(self.calls)
            if page > 2:
                return {"results": [], "has_more": False}
            return {
                "results": [
                    {"page": {"url": f"https://a.x.com/p{page}-{i}", "status": 200},
                     "task": {"time": "2026-09-01T00:00:00.000Z",
                              "url": f"https://a.x.com/p{page}-{i}"},
                     "sort": [page * 100 + i, "id"]}
                    for i in range(urlscan.PAGE_SIZE)
                ],
                "has_more": page < 2,
            }

    http = H()
    obs = urlscan.fetch_observations(http, "x.com", limit=150)
    assert len(obs) == 150
    assert len(http.calls) == 2
    assert "search_after=" in http.calls[1]


def test_dedupes_identical_page_and_task_urls():
    class H:
        def get_json(self, url):
            return {"results": [{
                "page": {"url": "https://a.x.com/p", "status": 200},
                "task": {"time": "2026-09-01T00:00:00.000Z",
                         "url": "https://a.x.com/p"},
            }], "has_more": False}

    obs = urlscan.fetch_observations(H(), "x.com")
    assert len(obs) == 1  # one URL, not the same one twice
