#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DoS-RESILIENCE test pages for the URL sandbox (defensive: verify the engine's guards, not to attack).

SAFETY: the amplification fan-out points ONLY at RFC 5737 TEST-NET documentation IPs (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) which are NON-ROUTABLE — the sandbox cannot flood any real host. No
zip bombs / entity-expansion weapons are produced. These pages exist so you can confirm the sandbox
CAPS / DEDUPS fetches, enforces a redirect hop-limit, and times out — i.e. that it does NOT get abused
as an amplifier or hung as a victim.

Output: docs/t1/ddos/*  ; prints the entry URLs to submit.
Usage: python3 ddos_cases.py [--base https://host] [--out docs]
"""
import argparse, os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASE = "https://commonaccount-test.github.io/UrlTestingNew"
ROOT = "t1/ddos"
TESTNET = ["192.0.2", "198.51.100", "203.0.113"]   # RFC 5737 — non-routable documentation ranges

PAGE = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n{head}</head>\n"
        "<body>\n<p><strong>TEST PAGE - URL SANDBOX QA (DoS resilience)</strong> - {title}</p>\n{body}\n</body>\n</html>\n")

def testnet_url(i, path="p"):
    block = TESTNET[i % len(TESTNET)]
    octet = (i % 254) + 1
    return "http://%s.%d/%s%d" % (block, octet, path, i)

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w", encoding="utf-8").write(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--out", default="docs")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = os.path.join(HERE, args.out)
    entries = []

    # 1) Amplification fan-out via <img> — 500 distinct non-routable hosts. Guard: cap/dedup fetches.
    imgs = "\n".join('<img src="%s" width="1" height="1">' % testnet_url(i, "img") for i in range(500))
    write(os.path.join(out, ROOT, "amp-img-fanout.html"), PAGE.format(title="amp img fan-out (500 -> TEST-NET)", head="", body=imgs))
    entries.append("amp-img-fanout.html")

    # 2) Amplification fan-out via <iframe> — 200 distinct non-routable hosts.
    ifr = "\n".join('<iframe src="%s" width="1" height="1"></iframe>' % testnet_url(i, "if") for i in range(200))
    write(os.path.join(out, ROOT, "amp-iframe-fanout.html"), PAGE.format(title="amp iframe fan-out (200 -> TEST-NET)", head="", body=ifr))
    entries.append("amp-iframe-fanout.html")

    # 3) Amplification fan-out via anchors — 1000 links (extraction/queue stress, no auto-fetch).
    anc = "\n".join('<a href="%s">l%d</a>' % (testnet_url(i, "a"), i) for i in range(1000))
    write(os.path.join(out, ROOT, "amp-links-1000.html"), PAGE.format(title="1000 anchors -> TEST-NET", head="", body=anc))
    entries.append("amp-links-1000.html")

    # 4) Long redirect chain — 50 hops (relative meta-refresh). Guard: hop-limit, no runaway.
    HOPS = 50
    for i in range(1, HOPS + 1):
        nxt = ("chain-%d.html" % (i + 1)) if i < HOPS else "chain-end.html"
        head = '<meta http-equiv="refresh" content="0;url=%s">\n' % nxt
        write(os.path.join(out, ROOT, "chain-%d.html" % i), PAGE.format(title="chain hop %d/%d" % (i, HOPS), head=head, body="redirecting..."))
    write(os.path.join(out, ROOT, "chain-end.html"), PAGE.format(title="chain end (benign)", head="", body="end of chain"))
    entries.append("chain-1.html")

    # 5) Redirect loop A<->B (relative). Guard: loop detection.
    write(os.path.join(out, ROOT, "loop-a.html"), PAGE.format(title="loop A", head='<meta http-equiv="refresh" content="0;url=loop-b.html">\n', body="A"))
    write(os.path.join(out, ROOT, "loop-b.html"), PAGE.format(title="loop B", head='<meta http-equiv="refresh" content="0;url=loop-a.html">\n', body="B"))
    entries.append("loop-a.html")

    write(os.path.join(out, ".nojekyll"), "")
    print("Submit these (all hosted on your site — deploy docs/ first):")
    for e in entries:
        print("  %s/%s/%s" % (base, ROOT, e))
    print("\nPlus this real external one for the slow-response (timeout) guard:")
    print("  https://httpbin.org/delay/30")
    print("\nExpected: sandbox CAPS fan-out fetches, enforces a redirect hop-limit, detects the loop, and")
    print("times out the slow one — it must NOT fetch all 500/1000 hosts or hang. (Resilience, not a verdict.)")


if __name__ == "__main__":
    main()
