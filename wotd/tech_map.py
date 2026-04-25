"""Map detected technology names (from httpx-pd / wappalyzergo) to wordlist keys.

Keys here correspond to /opt/wotd/wordlists/tech_{key}.txt installed by the Dockerfile.
Lookup is case-insensitive and strips the ':version' suffix httpx-pd appends.
"""

from __future__ import annotations

TECH_TO_WORDLIST: dict[str, str] = {
    "PHP": "php",
    "ASP.NET": "dotnet",
    "Java": "java",
    "Nginx": "nginx",
    "Apache": "apache",
    "Apache HTTP Server": "apache",
    "Apache Tomcat": "apache_tomcat",
    "Apache Axis": "apache_axis",
    "Jenkins": "jenkins",
    "Grafana": "grafana",
    "GitLab": "gitlab",
    "Kibana": "elasticsearch",
    "Elasticsearch": "elasticsearch",
    "Keycloak": "keycloak",
    "Kubernetes": "kubernetes",
    "Oracle WebLogic Server": "weblogic",
    "Oracle WebLogic": "weblogic",
    "WebLogic": "weblogic",
    "IBM WebSphere Application Server": "websphere",
    "IBM WebSphere": "websphere",
    "WebSphere": "websphere",
}

_LOOKUP = {k.lower(): v for k, v in TECH_TO_WORDLIST.items()}


def tech_to_wordlist_key(tech: str) -> str | None:
    """Return the wordlist key for a detected tech name, or None if no mapping exists.

    Strips the ':version' suffix httpx-pd appends and matches case-insensitively.
    """
    base = tech.split(":")[0].strip().lower()
    return _LOOKUP.get(base)
