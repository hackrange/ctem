"""Software names, normalized: one title per product, whatever version, edition or architecture a scanner reports.

"Mozilla Firefox (x64 en-US) 128.0.3", "Firefox ESR 115" and "Mozilla Firefox 129" are all the title
"Mozilla Firefox"; the versions stay on each install. Vendors lose their company suffixes ("Microsoft Corporation"
is "Microsoft"). Each title is also classed as third-party or system (the operating system, its updates, runtimes
and distribution packages that come with it), so the inventory can show third-party software by default."""
from __future__ import annotations

import re

# Bump with every change to the rules below: the hourly maintenance job then regroups what's stored once
# (api/maintenance/renormalize_software.py), carrying review decisions and exceptions to the new titles
RULES_VERSION = 2

_SUFFIX = re.compile(r"[,\s]+(inc|incorporated|corp|corporation|co|company|llc|l\.l\.c|ltd|limited|gmbh|ag|s\.a|sa|bv|"
                     r"b\.v|plc|pty|srl|s\.r\.l|s\.r\.o|sro|spol|oy|ab|as|kk|nv|n\.v|pte|sas|spa|s\.p\.a|ltda|sl|s\.l|a\.s)\.?$", re.I)
_ALIASES = {"microsoft corporation": "Microsoft", "google llc": "Google", "google inc": "Google", "mozilla": "Mozilla",
            "the mozilla organization": "Mozilla", "adobe systems": "Adobe", "adobe systems incorporated": "Adobe",
            "oracle america": "Oracle", "oracle corporation": "Oracle", "vmware": "VMware", "vmware, inc.": "VMware",
            "apple": "Apple", "apple inc": "Apple", "cisco systems": "Cisco", "zoom video communications": "Zoom",
            "the apache software foundation": "Apache", "apache software foundation": "Apache",
            "hewlett-packard": "HP", "hewlett packard": "HP", "hewlett-packard development company": "HP",
            "hewlett packard enterprise": "HPE", "hp inc": "HP", "adobe inc": "Adobe", "citrix systems": "Citrix",
            "dell inc": "Dell", "dell technologies": "Dell", "lenovo group": "Lenovo"}
# Words that don't identify a vendor in a product name ("Reolink" does for "Shenzhen Reolink Technology")
_GENERIC = {"the", "software", "technology", "technologies", "systems", "solutions", "group", "international",
            "development", "computer", "corporation", "labs", "studio", "studios", "digital", "network", "networks",
            "foundation", "team", "project", "community"}
_HOST = re.compile(r"\s+[a-z0-9-]+(?:\.[a-z0-9-]+){2,}\s*$", re.I)   # a server name some installers append
_ARCH = re.compile(r"\([^()]*\b(?:x64|x86|amd64|arm64|64-bit|32-bit|[a-z]{2}-[a-z]{2})\b[^()]*\)|"
                   r"\b(?:x64|x86|amd64|arm64|win64|win32|64-bit|32-bit|64 bit|32 bit)\b", re.I)
_EMPTY = re.compile(r"\(\s*\)|\[\s*\]|\s+-\s+[a-z]{2}-[a-z]{2}\s*$", re.I)
_VERSION = re.compile(r"(?:\s+|-|_)v?\d+(?:[._]\d+)+[a-z0-9.\-+_]*\s*$|(?:\s+)v?\d+\s*$|\s+(?:19|20)\d{2}\s*$", re.I)
# Editions and channels of the same product (Office Professional Plus and Office are one title)
_EDITION = re.compile(r"\s+(?:esr|lts|x64 edition|update(?: \d+)?|professional plus|professional|standard|enterprise|"
                      r"business|home and business|home and student|ultimate|community edition|community|premium|"
                      r"pro plus|stable|beta|insider|preview)\s*$", re.I)
_SPACE = re.compile(r"\s{2,}")

# System: what comes with the operating system rather than software someone chose to install
_SYSTEM_VENDORS = {"red hat", "canonical", "debian", "ubuntu", "centos", "suse", "opensuse", "fedora", "rocky",
                   "almalinux", "amazon linux", "oracle linux", "the centos project", "debian project", "gentoo",
                   "alpine", "freebsd"}
_SYSTEM_NAMES = re.compile(
    r"^(windows\b|microsoft windows\b|microsoft \.net|\.net (framework|runtime|desktop runtime)|microsoft visual c\+\+ .*"
    r"redistributable|visual c\+\+ .*redistributable|microsoft update health|update for |security update for |hotfix for |"
    r"kb\d{6,}|microsoft edge webview2 runtime|windows sdk|windows driver|microsoft vc\+\+|vcredist|"
    r"microsoft (directx|silverlight|xml parser|core xml|gdi\+)|microsoft policy platform|microsoft windows desktop runtime)",
    re.I)


def vendor(raw: str | None) -> str:
    v = " ".join(str(raw or "").replace("®", "").replace("™", "").split()).strip(" ,.")
    if not v or re.search(r"[\\/]", v):   # a registry or file path some installers leave as the publisher
        return ""
    low = v.lower()
    if low in _ALIASES:
        return _ALIASES[low]
    for _ in range(2):
        v = _SUFFIX.sub("", v).strip(" ,.")
    return _ALIASES.get(v.lower(), v)


def title(name: str | None, vendor_name: str = "") -> str:
    """The product name without version, edition, language or architecture, led by its vendor."""
    n = " ".join(str(name or "").replace("®", "").replace("™", "").split())
    for _ in range(3):
        before = n
        n = _EMPTY.sub(" ", _ARCH.sub(" ", _HOST.sub("", n)))
        n = _SPACE.sub(" ", n).strip(" -_,")
        n = _VERSION.sub("", n).strip(" -_,")
        cut = _EDITION.sub("", n).strip(" -_,")
        if not re.search(r"\b(for|and|of|the|with)$", cut, re.I):   # "Apps for enterprise" keeps its last word
            n = cut
        if n == before:
            break
    if not n:
        return ""
    words = [w for w in re.findall(r"[a-z0-9+]+", vendor_name.lower()) if w not in _GENERIC and len(w) > 1]
    named = set(re.findall(r"[a-z0-9+]+", n.lower()))
    if words and not named & set(words) and not vendor_name.lower().startswith("the "):   # led by its vendor
        # unless the name already says who makes it (or the vendor is an organization: "The Document Foundation")
        n = f"{vendor_name} {n}"
    return n[:200]


def key(vendor_name: str, title_name: str) -> str:
    return f"{vendor_name.lower()}|{title_name.lower()}"[:300]


def system(vendor_name: str, title_name: str, kind: str | None = None, cpe: str | None = None) -> bool:
    """The OS, its updates and runtimes, and distribution packages: not third-party software."""
    if (cpe or "").lower().startswith(("cpe:/o:", "cpe:2.3:o:")):
        return True
    if (kind or "").strip().lower() in ("os", "operating system", "package", "patch", "hotfix"):
        return True
    if vendor_name.lower() in _SYSTEM_VENDORS:
        return True
    bare = title_name[len(vendor_name):].strip() if vendor_name and title_name.lower().startswith(vendor_name.lower()) else title_name
    return bool(_SYSTEM_NAMES.match(title_name) or _SYSTEM_NAMES.match(bare))


def normalize(vendor_raw: str | None, product: str | None, family: str | None = None, kind: str | None = None,
              cpe: str | None = None) -> dict | None:
    """{key, vendor, title, system} for one reported piece of software, or None when there's no usable name."""
    v = vendor(vendor_raw)
    t = title(family or product, v) or title(product, v)
    if not t:
        return None
    return {"key": key(v, t), "vendor": v[:200], "title": t, "system": system(v, t, kind, cpe)}
