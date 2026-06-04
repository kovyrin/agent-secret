#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"

PROJECT_ROOT="$project_root" python3 <<'PY'
from __future__ import annotations

from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
import os
import sys
import xml.etree.ElementTree as ET


SITE_ORIGIN = "https://agent-secret.sh"
SITEMAP_URL = f"{SITE_ORIGIN}/sitemap.xml"
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"

project_root = Path(os.environ["PROJECT_ROOT"])
site_dir = project_root / "site"
errors: list[str] = []


class CanonicalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.canonical: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "link":
            return

        attrs_dict = {key: value for key, value in attrs}
        rel = attrs_dict.get("rel")
        href = attrs_dict.get("href")
        if rel == "canonical" and href:
            self.canonical = href


def html_canonicals() -> set[str]:
    urls: set[str] = set()
    for html in sorted(site_dir.glob("*.html")):
        parser = CanonicalParser()
        parser.feed(html.read_text())
        if parser.canonical is None:
            errors.append(f"{html.relative_to(project_root)} is missing a canonical link")
            continue

        parsed = urlparse(parser.canonical)
        if parsed.scheme != "https" or parsed.netloc != "agent-secret.sh":
            errors.append(
                f"{html.relative_to(project_root)} canonical must use {SITE_ORIGIN}: "
                f"{parser.canonical}"
            )
            continue
        if parsed.query or parsed.fragment:
            errors.append(
                f"{html.relative_to(project_root)} canonical must not include query "
                f"or fragment: {parser.canonical}"
            )
            continue

        urls.add(parser.canonical)

    return urls


def sitemap_urls() -> set[str]:
    sitemap = site_dir / "sitemap.xml"
    try:
        root = ET.parse(sitemap).getroot()
    except ET.ParseError as exc:
        errors.append(f"site/sitemap.xml is not valid XML: {exc}")
        return set()

    if root.tag != f"{{{SITEMAP_NS}}}urlset":
        errors.append("site/sitemap.xml root must be a sitemap urlset")
        return set()

    urls: set[str] = set()
    for url_node in root.findall(f"{{{SITEMAP_NS}}}url"):
        locs = url_node.findall(f"{{{SITEMAP_NS}}}loc")
        if len(locs) != 1:
            errors.append("each sitemap url entry must contain exactly one loc")
            continue

        loc = (locs[0].text or "").strip()
        if not loc:
            errors.append("sitemap loc must not be empty")
            continue
        if loc in urls:
            errors.append(f"duplicate sitemap loc: {loc}")
        urls.add(loc)

        lastmods = url_node.findall(f"{{{SITEMAP_NS}}}lastmod")
        if len(lastmods) > 1:
            errors.append(f"{loc} has more than one lastmod")
            continue
        if lastmods:
            raw_lastmod = (lastmods[0].text or "").strip()
            try:
                date.fromisoformat(raw_lastmod)
            except ValueError:
                errors.append(f"{loc} lastmod must be YYYY-MM-DD: {raw_lastmod}")

    return urls


def check_robots() -> None:
    robots = site_dir / "robots.txt"
    lines = [line.strip() for line in robots.read_text().splitlines()]
    if f"Sitemap: {SITEMAP_URL}" not in lines:
        errors.append(f"site/robots.txt must reference {SITEMAP_URL}")


expected = html_canonicals()
actual = sitemap_urls()
check_robots()

missing = sorted(expected - actual)
extra = sorted(actual - expected)
if missing:
    errors.append("sitemap is missing canonical URLs: " + ", ".join(missing))
if extra:
    errors.append("sitemap contains non-canonical URLs: " + ", ".join(extra))

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)

print("test-site-sitemap: ok")
PY
