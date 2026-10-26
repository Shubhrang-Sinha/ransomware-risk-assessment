"""
threat_intel.py - turns a vulnerability scan into evidence about LIKELIHOOD.

CISA's "Known Exploited Vulnerabilities" (KEV) catalog is a free, public list of
software flaws that attackers are ACTIVELY using. A flaw on that list is not just
"possible" to exploit - it is being exploited right now.
"""
import json
import urllib.request


def load_kev(feed_url, fallback_path, timeout=8, use_online=True):
    """Return (set_of_cve_ids, label). Tries the live feed, falls back to a local file."""
    if use_online:
        try:
            req = urllib.request.Request(feed_url, headers={"User-Agent": "risk-assessment-tool"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
            return {v["cveID"].upper() for v in data["vulnerabilities"]}, "CISA live feed"
        except Exception:
            pass  # offline / blocked network -> use the local sample
    with open(fallback_path, encoding="utf-8") as f:
        data = json.load(f)
    return {v["cveID"].upper() for v in data["vulnerabilities"]}, "local sample subset (offline)"


def match_vulns(vulns, kev_set):
    out = vulns.copy()
    out["in_kev"] = out["cve"].isin(kev_set)
    return out


def summarise(matched):
    kev = matched[matched["in_kev"]]
    return {"total": int(len(matched)),
            "kev_total": int(len(kev)),
            "kev_internet": int(kev["internet_facing"].sum()),
            "kev_internal": int((~kev["internet_facing"]).sum())}
