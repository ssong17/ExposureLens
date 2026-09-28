"""Detection rules for the passive exposure scanner.

Three rule sets, all matched against data already collected (never by touching
the target): sensitive hostnames, sensitive URL paths, and secrets leaked in
URL query strings. Patterns are deliberately high-signal to limit noise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern[str]


def _rules(specs: list[tuple[str, str, str, str]]) -> list[Rule]:
    return [Rule(i, c, s, re.compile(p, re.IGNORECASE)) for i, c, s, p in specs]


# Rules whose match is a *shape* anyone could write by accident — a quoted
# assignment, a bearer header, a query parameter. Their hits are checked against
# the placeholder list and an entropy floor before being reported, because a
# minified bundle is full of `password:""`, `apiKey:"YOUR_API_KEY"` and doc
# samples. Structurally unique prefixes (AKIA, ghp_, sk_live_, AIza) are exempt:
# the prefix is already the proof.
ENTROPY_CHECKED_RULES = frozenset(
    {
        "body-assigned-secret",
        "body-django-secret",
        "body-bearer",
        "body-basic-auth",
        "body-aws-secret",
        "secret-in-query",
    }
)

# Values that match a secret shape but carry no secret. Compared case-folded
# against the extracted value.
PLACEHOLDER_TOKENS = frozenset(
    {
        "your", "yours", "example", "examples", "placeholder", "changeme",
        "todo", "tbd", "dummy", "sample", "fake", "test", "testing", "insert",
        "replace", "redacted", "removed", "hidden", "secret", "password",
        "passwd", "token", "apikey", "key", "value", "string", "none", "null",
        "undefined", "nil", "empty", "default", "foo", "bar", "baz", "lorem",
        "ipsum", "xxx", "abc", "asdf", "qwerty", "mysecret", "mypassword",
    }
)

# Templating/interpolation markers: the real value is injected at runtime.
PLACEHOLDER_MARKERS = ("${", "{{", "<%", "%s", "%(", "#{", "</", "[your", "<your")

# Minimum Shannon entropy (bits per character) for a generic secret shape to be
# believable. Real keys are near-random; "administrator" and "changeme123" are not.
MIN_SECRET_ENTROPY = 3.0

# Values that are public by design even when a generic secret rule matches the
# key name wrapped around them: Google browser keys (AIza…, shared by GA / Maps
# / Firebase) and reCAPTCHA site keys (6L…). These are recorded elsewhere as
# low-severity backend-config surface; here they are excluded from the generic
# hardcoded-secret rules so a public GA/Firebase/reCAPTCHA key never tops a
# report as a leaked credential (the exact call every field report made by hand).
PUBLIC_BROWSER_KEY = re.compile(r"^(?:AIza[0-9A-Za-z_\-]{35}|6L[0-9A-Za-z_\-]{38})$")

# Cap on hits recorded per rule per body. One webpack bundle can reference
# hundreds of routes; the first N establish the surface, the rest are volume.
MAX_MATCHES_PER_RULE = 25


# Matched against the hostname of subdomain assets.
HOST_RULES = _rules(
    [
        ("host-vcs", "sensitive-host", "high", r"^(git|gitlab|gitea|svn)\."),
        ("host-ci", "sensitive-host", "high", r"^(jenkins|drone|teamcity|bamboo)\."),
        ("host-db-admin", "sensitive-host", "high", r"^(phpmyadmin|adminer|pma)\."),
        ("host-monitoring", "sensitive-host", "high", r"^(grafana|kibana|prometheus)\."),
        ("host-remote", "sensitive-host", "high", r"^(vpn|rdp|citrix|owa)\."),
        ("host-nonprod", "sensitive-host", "medium", r"^(dev|test|stage|staging|qa|uat|sandbox)\."),
        ("host-internal", "sensitive-host", "medium", r"^(internal|intra|admin|mgmt|backup)\."),
    ]
)

# Matched against the path of endpoint URLs.
PATH_RULES = _rules(
    [
        ("path-secret-file", "secret-file", "critical",
         r"/(\.env|\.htpasswd|\.npmrc|\.dockercfg|id_rsa|id_dsa)(\b|$)"
         r"|\.(pem|key|p12|pfx|keystore|ppk)$|/\.aws/credentials"),
        ("path-vcs", "vcs-exposure", "high", r"/\.(git|svn|hg)(/|$)"),
        ("path-config", "config-exposure", "high",
         r"/(wp-config\.php|config\.(json|ya?ml|php|xml)|settings\.py"
         r"|application\.(properties|ya?ml)|web\.config|\.git-credentials)(\b|$)"),
        ("path-backup", "backup-exposure", "high",
         r"\.(sql|sql\.gz|bak|old|backup|swp|tar\.gz|zip)$|/(backup|dump)(/|s?\b)"),
        ("path-debug", "debug-exposure", "high",
         r"/(phpinfo|server-status|actuator(/|$)|\.DS_Store|env\.js)"),
        ("path-admin", "admin-panel", "medium",
         r"/(admin|wp-admin|phpmyadmin|administrator)(/|$)"),
        ("path-api", "api-surface", "low",
         r"/(swagger|openapi\.(json|ya?ml)|api-docs|graphql)(/|$|\.)"),
    ]
)

# Matched against the whole endpoint URL (query strings mostly).
SECRET_RULES = _rules(
    [
        ("secret-aws-akid", "leaked-secret", "critical", r"AKIA[0-9A-Z]{16}"),
        ("secret-slack", "leaked-secret", "critical", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
        ("secret-private-key", "leaked-secret", "critical",
         r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        # See body-google-api: an AIza key is a public browser key. In a URL it
        # is a little more suspect (log leakage) than in a bundle, but GA/Maps
        # embeds carry it too, so it is medium, not a high leaked secret.
        ("secret-google-api", "backend-config", "medium", r"AIza[0-9A-Za-z_\-]{35}"),
        ("secret-jwt", "leaked-secret", "high",
         r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        ("secret-in-query", "leaked-secret", "high",
         r"(?:api_?key|access_?token|auth_?token|secret|password|passwd)=[^&\s]{6,}"),
    ]
)

# Matched against RESPONSE BODIES (JS bundles, config files, JSON responses,
# archived pages). This is what `inspect` runs after reading a body — the URL
# rules above only see the address, these see what the address serves. Patterns
# stay high-signal because bodies are large and noisy; every match is masked
# before it is recorded, and secrets are never verified.
CONTENT_RULES = _rules(
    [
        # Hard-coded cloud/service credentials.
        ("body-aws-akid", "leaked-secret", "critical", r"AKIA[0-9A-Z]{16}"),
        ("body-aws-secret", "leaked-secret", "critical",
         r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']"),
        ("body-slack", "leaked-secret", "critical", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
        ("body-private-key", "leaked-secret", "critical",
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        # A Google "AIza" key is a browser-exposed, referrer-restricted key
        # shared by GA, Maps and Firebase — public by design. Field recon
        # consistently judged these (especially inside GA/GTM script) as noise,
        # not a leak, so it is recorded as low-severity surface rather than a
        # high leaked secret. A genuinely over-privileged key still appears; it
        # is just ranked honestly instead of topping the report.
        ("body-google-api", "backend-config", "low", r"AIza[0-9A-Za-z_\-]{35}"),
        ("body-jwt", "leaked-secret", "high",
         r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        # Generic hard-coded secret assignments in code/config.
        ("body-assigned-secret", "hardcoded-secret", "high",
         r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token"
         r"|client[_-]?secret|private[_-]?key|password|passwd)"
         r"[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
        ("body-django-secret", "hardcoded-secret", "high",
         r"(?i)SECRET_KEY\s*[:=]\s*[\"'][^\"']{12,}[\"']"),
        # Backend / DB configuration leaked in a served body.
        ("body-db-uri", "db-exposure", "critical",
         r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)"
         r"://[^\s\"'<>]*:[^\s\"'<>@/]+@[^\s\"'<>/]+"),
        ("body-jdbc-uri", "db-exposure", "high",
         r"(?i)jdbc:[a-z0-9]+://[^\s\"'<>]+"),
        # Real SQL structure only — "INSERT INTO <t> ... VALUES" / "CREATE TABLE
        # <t> (" — so English prose like a code comment "insert into internal…"
        # no longer matches.
        ("body-sql-dump", "db-exposure", "high",
         r"INSERT\s+INTO\s+[`\"\[]?\w+[`\"\]]?\s*(?:\([^)]{0,300}\)\s*)?VALUES\b"
         r"|CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?\w+[`\"\]]?\s*\("
         r"|DROP\s+TABLE\s+IF\s+EXISTS\s+[`\"\[]?\w+"),
        # PII: Korean RRN. The date part (YYMMDD) is validated so 13-digit unix
        # timestamps / ids (e.g. 1552553413651) no longer false-match.
        ("body-krrn", "pii-exposure", "high",
         r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?[1-4]\d{6}(?!\d)"),
        # More credential shapes — recall-first: better to over-flag than miss.
        ("body-github-token", "leaked-secret", "critical", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("body-stripe-key", "leaked-secret", "critical", r"sk_live_[0-9A-Za-z]{16,}"),
        ("body-bearer", "leaked-secret", "high",
         r"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}=*"),
        ("body-basic-auth", "leaked-secret", "high",
         r"(?i)authorization[\"']?\s*[:=]\s*[\"']?basic\s+[A-Za-z0-9+/]{16,}={0,2}"),
    ]
)

# Recall-focused signals for `inspect` on client code (JS bundles, source maps,
# HTML). These map the app's own attack surface — the part host/URL names cannot
# reach. They are NOT masked (the value IS the finding: a route, a URL, a check),
# and they lean toward over-flagging on purpose: missing a real exposure costs
# more than a noisy candidate.
CLIENT_RULES = _rules(
    [
        # Client-side authorization checks. If the server does not re-enforce the
        # same check, this route is a broken-access-control candidate to review.
        ("js-client-authz", "client-authz", "medium",
         # Whole-identifier only: a trailing \b keeps framework internals like
         # Vue's `isRootInsert` from matching `isRoot`.
         r"\b(?:is_?admin|is_?staff|is_?superuser|is_?root|has_?role"
         r"|has_?permission|is_?authori[sz]ed|check_?permission|require_?auth"
         r"|require_?login)\b"
         r"|role\s*[=:]{1,3}\s*[\"'](?:admin|superuser|root|staff|manager)[\"']"),
        # A source map means the whole frontend source can be reconstructed.
        ("js-sourcemap", "sourcemap", "medium",
         r"(?i)//[#@]\s*sourceMappingURL=\S+"),
        # Internal / non-public URLs leaked into shipped client code.
        ("js-internal-url", "internal-url", "medium",
         r"(?i)https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
         r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
         r"|[a-z0-9.-]+\.(?:internal|local|corp|intra|intranet))[^\s\"'<>]*"),
        # API/admin routes referenced in client code — the app's surface map.
        ("js-api-route", "api-endpoint", "low",
         r"[\"'](/(?:api|rest|graphql|internal|admin|v\d+)/[A-Za-z0-9_./:{}-]{1,100})[\"']"),
        # Self-owned backend base URL shipped in client config (Next.js/Nuxt env,
        # window.__ENV__, a config object). Not a secret, but it maps the app's
        # real backend — the single highest-value thing recon pulls from a
        # bundle (e.g. hancom's BACKEND_API_URL=www-api.hancom.com). The key name
        # must end in URL/HOST/ENDPOINT and the value must be an http(s) URL, so
        # analytics/CDN script srcs (GA, GTM, fonts) do not match. Kept verbatim
        # (the address IS the finding), never masked.
        ("js-backend-url", "backend-config", "medium",
         r"(?i)[\"']?\b(?:backend|api|server|gateway|store|auth|base)_?[a-z]*_?"
         r"(?:url|host|endpoint)\b[\"']?\s*[:=]\s*[\"']https?://[^\"'\s]{4,}[\"']"),
        # Custom API-auth header names betray the app's own auth scheme even when
        # the value is absent — e.g. X-HC-API-KEY / X-HC-CLIENT-ID. A standard
        # header (X-Frame-Options, X-Requested-With, X-CSRF-Token) is excluded.
        ("js-custom-auth-header", "backend-config", "low",
         r"(?i)[\"']x-(?!frame-|xss-|content-|requested-|forwarded-|csrf-|real-ip)"
         r"[a-z0-9]{1,16}-(?:api-key|client-id|client-secret|auth-token|secret|token)[\"']"),
        # Firebase project config shipped to the browser. The apiKey (AIza) is
        # public by design, but the bucket/database endpoints map real backend
        # storage whose exposure depends on Security Rules — worth surfacing as
        # an attack-surface fact, not a secret. Value kept verbatim.
        ("js-firebase-config", "backend-config", "medium",
         r"(?i)(?:databaseURL|storageBucket)[\"']?\s*[:=]\s*[\"'][^\"'\s]+[\"']"
         r"|[a-z0-9][a-z0-9-]{2,}\.(?:firebaseio\.com|firebaseapp\.com|appspot\.com)"),
        # Supabase project endpoint — same idea: the anon URL maps the backend.
        ("js-supabase", "backend-config", "medium",
         r"(?i)https?://[a-z0-9]{8,}\.supabase\.(?:co|in|net)"),
    ]
)

# Known-exposure probes for `verify`, keyed by the scan rule that flagged a
# sensitive host. Each entry is an EXACT path the finding already implies — never
# a guessed word or a wordlist — so verification stays targeted: a git host is
# only checked at /.git/config, a CI host at its own API. "/" confirms whether a
# service that should be gated answers at all. Severity is the weight IF the path
# is reachable unauthenticated (2xx); otherwise verify only records liveness.
VERIFY_PROBES: dict[str, list[tuple[str, str, str, str]]] = {
    # (path, severity, category, rule_id)
    "host-vcs": [
        ("/.git/config", "high", "vcs-exposure", "verify-git-config"),
        ("/.git/HEAD", "high", "vcs-exposure", "verify-git-head"),
    ],
    "host-ci": [
        ("/", "medium", "exposed-service", "verify-ci-root"),
        ("/api/json", "high", "exposed-service", "verify-ci-api"),
    ],
    "host-db-admin": [("/", "high", "exposed-service", "verify-db-admin-root")],
    "host-monitoring": [("/", "medium", "exposed-service", "verify-monitoring-root")],
    "host-remote": [("/", "medium", "exposed-service", "verify-remote-root")],
    "host-internal": [("/", "medium", "exposed-service", "verify-internal-root")],
    "host-nonprod": [("/", "low", "exposed-service", "verify-nonprod-root")],
}

# Fallback for a sensitive host whose rule has no specific probe list.
VERIFY_DEFAULT_PROBE = [("/", "low", "exposed-service", "verify-root")]

# Internet-facing ports that should almost never be public. Used by `services`
# to turn Shodan InternetDB's CURRENT port list into findings — this is present
# exposure (a third party scanned it recently), not an archived trace.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    23: ("high", "telnet"), 21: ("medium", "ftp"), 445: ("high", "smb"),
    3389: ("high", "rdp"), 5900: ("high", "vnc"), 512: ("high", "rexec"),
    3306: ("critical", "mysql"), 5432: ("critical", "postgres"),
    1433: ("critical", "mssql"), 1521: ("critical", "oracle-db"),
    6379: ("critical", "redis"), 27017: ("critical", "mongodb"),
    9200: ("critical", "elasticsearch"), 9300: ("high", "elasticsearch-transport"),
    5984: ("critical", "couchdb"), 11211: ("critical", "memcached"),
    8086: ("high", "influxdb"), 9092: ("high", "kafka"), 2181: ("high", "zookeeper"),
    5601: ("high", "kibana"), 15672: ("high", "rabbitmq-mgmt"),
    2375: ("critical", "docker-api"), 2376: ("critical", "docker-api"),
    6443: ("high", "kubernetes-api"), 10250: ("high", "kubelet"),
    7001: ("high", "weblogic"), 8161: ("medium", "activemq"),
    50070: ("high", "hadoop-hdfs"), 9000: ("medium", "service-9000"),
}


# Path patterns that should sit behind authentication. `inspect --source fetch`
# flags one of these only when the live status code says it is reachable
# unauthenticated (2xx) instead of challenged (301/302/401/403).
AUTHZ_PATH = re.compile(
    r"/(admin|wp-admin|administrator|phpmyadmin|adminer|manager|dashboard"
    r"|actuator|grafana|kibana|console|internal|private|api/(?:v\d+/)?(?:users?|admin))"
    r"(/|$)",
    re.IGNORECASE,
)


# Human-readable name for every category a rule can emit. A report line reading
# "[backup-exposure]" tells the reader nothing about WHAT was found; the point of
# a finding is the kind of sensitive thing exposed, so that is what gets printed.
# Keyed by the `category` field on a Finding; the raw slug stays in the JSONL for
# machines and for grepping.
CATEGORY_LABELS: dict[str, str] = {
    # credentials and other directly usable secrets
    "leaked-secret": "유출된 자격증명",
    "hardcoded-secret": "코드에 박힌 자격증명",
    "secret-file": "시크릿 파일(.env·개인키)",
    "db-exposure": "DB 접속정보",
    "pii-exposure": "개인정보(주민번호 등)",
    # files and paths that should not be served
    "vcs-exposure": "소스 저장소 노출(.git)",
    "config-exposure": "설정 파일 노출",
    "backup-exposure": "백업·덤프 파일",
    "debug-exposure": "디버그·상태 페이지",
    "admin-panel": "관리자 페이지",
    "api-surface": "API 문서·스키마",
    # application surface recovered from client code
    "client-authz": "클라이언트 권한 체크",
    "internal-url": "내부 주소 노출",
    "api-endpoint": "API 경로",
    "backend-config": "백엔드 설정 노출(주소·인증방식)",
    "sourcemap": "소스맵(원본 복원 가능)",
    # network-level and live-checked facts
    "sensitive-host": "민감 호스트(이름 기반 후보)",
    "exposed-service": "열린 서비스 포트",
    "shared-service": "열린 포트(공유 IP·귀속 미확정)",
    "access-control": "인증 없이 열린 경로",
    "liveness": "접속 상태",
}


def category_label(category: str) -> str:
    """Readable name for a category, falling back to the raw slug."""
    return CATEGORY_LABELS.get(category, category)
