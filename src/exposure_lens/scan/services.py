"""Current-exposure check: collected IPs -> Shodan InternetDB -> findings.

Where the `scan` archived-body pass reads the past, this reads what a third-party
scanner (Shodan) sees on our IPs right now: internet-facing databases, caches and
admin services. It never contacts the target — Shodan already did the scanning;
we only read its result — but present-tense, which is what an attacker actually
acts on.

Attribution is the hard part here. An open 3306 on an IP is only *this* org's
exposure if the IP is *this* org's. On shared hosting or a CDN edge, dozens of
unrelated tenants answer on one address, so reporting that port as the org's
critical finding is wrong and, for a tool that later probes what it reports,
irresponsible. So every IP is classified first (``classify_ip``): a shared or
cross-org address keeps its finding but is downgraded and labelled, and the ASN
that actually owns the address is recorded as evidence either way.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable

from ..core.models import (
    SEVERITY_ORDER,
    Finding,
    downgrade,
    run_date,
    timestamp_now,
)
from ..core.net import Http, NetworkDown, RequestBudgetExceeded
from ..sources import shodan
from .rules import RISKY_PORTS

# Above this many distinct hostnames on one address, it is shared infrastructure
# (virtual hosting / CDN edge), not a machine this org alone runs.
SHARED_HOST_LIMIT = 8


@dataclass
class IpInfo:
    """What the collected assets say about one resolved address."""

    ip: str
    hosts: list[str] = field(default_factory=list)
    orgs: list[str] = field(default_factory=list)
    org_names: dict[str, str] = field(default_factory=dict)
    asn: str = ""

    @property
    def org_id(self) -> str:
        return self.orgs[0] if self.orgs else ""

    @property
    def org_name(self) -> str:
        return self.org_names.get(self.org_id, "")

    @property
    def primary_host(self) -> str:
        # Shortest name, then alphabetical: deterministic, and the shortest host
        # on an address is the apex-most one rather than an arbitrary first hit.
        return min(self.hosts, key=lambda h: (len(h), h)) if self.hosts else self.ip

    def classify(self) -> tuple[bool, str]:
        """(is_shared, reason). Shared = attribution to one org is not safe."""
        if len(self.orgs) > 1:
            return True, f"shared across orgs: {', '.join(sorted(self.orgs))}"
        if len(self.hosts) > SHARED_HOST_LIMIT:
            return True, f"{len(self.hosts)} hostnames on one address"
        return False, ""


def build_ip_index(assets: list[dict]) -> dict[str, IpInfo]:
    """resolved_ip -> IpInfo, gathering every host/org/ASN seen on that address."""
    index: dict[str, IpInfo] = {}
    for asset in assets:
        ip = asset.get("resolved_ip", "")
        if not ip:
            continue
        info = index.setdefault(ip, IpInfo(ip=ip))
        host = asset.get("host", "")
        if host and host not in info.hosts:
            info.hosts.append(host)
        org = asset.get("org_id", "")
        if org and org not in info.orgs:
            info.orgs.append(org)
        if org and asset.get("org_name"):
            info.org_names.setdefault(org, asset["org_name"])
        if not info.asn and asset.get("asn"):
            info.asn = asset["asn"]
    return index


def check_exposure(
    http: Http,
    ip_index: dict[str, IpInfo],
    *,
    min_severity: str = "medium",
    max_ips: int = 0,  # 0 = unlimited
    log: Callable[[str], None] | None = None,
    answers: dict[str, dict | None] | None = None,
    on_answer: Callable[[str, dict | None], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Return (findings, problems) from InternetDB records for the given IPs.

    ``answers`` are records an interrupted run already fetched (ip -> record,
    None = no data); those IPs are not queried again. ``on_answer`` is told
    every new answer so the caller can persist it. An IP whose query failed is
    reported in problems and NOT passed to ``on_answer``, so a resume retries
    it. ``NetworkDown`` propagates.
    """
    say = log or (lambda _: None)
    limit = SEVERITY_ORDER[min_severity]
    findings: list[Finding] = []
    problems: list[str] = []

    ips = sorted(ip_index)
    if max_ips and len(ips) > max_ips:
        problems.append(f"capped IPs {max_ips}/{len(ips)}")
        ips = ips[:max_ips]

    answers = answers or {}
    reused = sum(1 for ip in ips if ip in answers)
    say(
        f"querying Shodan InternetDB for {len(ips) - reused} IPs"
        + (f" ({reused} reused from the interrupted run)..." if reused else "...")
    )
    shared_count = 0
    failed: list[str] = []

    def _add(info: IpInfo, severity: str, rule: str, label: str, port: int) -> None:
        nonlocal shared_count
        is_shared, reason = info.classify()
        evidence = f"{info.ip}:{port} {label} (open now)"
        if info.asn:
            evidence += f" {info.asn}"
        if is_shared:
            # The port is real; whose it is, is not established. Say so in the
            # row rather than claiming it as this org's critical finding.
            severity = downgrade(severity)
            evidence += f" [shared-ip: {reason}; owner unconfirmed]"
        if SEVERITY_ORDER[severity] > limit:
            return
        if is_shared:
            shared_count += 1
        findings.append(
            Finding(
                finding_id=f"S_{run_date()}_{len(findings) + 1:06d}",
                org_id=info.org_id,
                asset_ref=info.ip,
                org_name=info.org_name,
                severity=severity,  # type: ignore[arg-type]
                category="shared-service" if is_shared else "exposed-service",
                rule=rule,
                host=info.primary_host,
                url="",
                evidence=evidence,
                discovered_at=timestamp_now(),
                status="",
                source="shodan-internetdb",
                # Shodan only reports what it observed recently, so anything it
                # returns is present-tense by construction.
                freshness="current",
            )
        )

    for i, ip in enumerate(ips, 1):
        if ip in answers:
            data = answers[ip]
        else:
            if http.max_requests and http.request_count >= http.max_requests:
                problems.append("stopped at request cap")
                break
            try:
                data = shodan.internetdb(http, ip)
            except NetworkDown:
                raise
            except RequestBudgetExceeded:
                problems.append("stopped at request cap")
                break
            except Exception as exc:  # noqa: BLE001 - one IP failing is not fatal
                failed.append(ip)
                say(f"  ({i}/{len(ips)}) {ip}: query failed ({exc})")
                continue
            if on_answer:
                on_answer(ip, data)
        if not data:
            continue
        # Only report OPEN PORTS — a fact Shodan actually observed. InternetDB's
        # `vulns` are inferred from version banners, not confirmed exploitable,
        # so we do not report them.
        ports = data.get("ports", []) or []
        say(f"  ({i}/{len(ips)}) {ip}: {len(ports)} ports open")
        for port in ports:
            spec = RISKY_PORTS.get(port)
            if spec:
                severity, label = spec
                _add(ip_index[ip], severity, f"port-{port}", label, port)

    if failed:
        problems.append(
            f"Shodan 조회 실패 {len(failed)}개 IP (결과 없음으로 취급하지 않음): "
            f"{', '.join(failed[:10])}{' ...' if len(failed) > 10 else ''}"
        )
    if shared_count:
        problems.append(
            f"{shared_count} service findings sit on shared/CDN addresses and were "
            "downgraded (ownership unconfirmed)"
        )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    say(f"done: {len(findings)} findings from {len(ips)} IPs")
    return findings, problems

