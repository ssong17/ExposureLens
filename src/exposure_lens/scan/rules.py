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
        ("secret-google-api", "leaked-secret", "high", r"AIza[0-9A-Za-z_\-]{35}"),
        ("secret-jwt", "leaked-secret", "high",
         r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        ("secret-in-query", "leaked-secret", "high",
         r"(?:api_?key|access_?token|auth_?token|secret|password|passwd)=[^&\s]{6,}"),
    ]
)
