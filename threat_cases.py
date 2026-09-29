#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat-scenario generator for the URL-sandbox test site (SEPARATE from build_cases.py / generate.py,
which cover URL *extraction*). This builds live pages the sandbox FETCHES and RENDERS so we can assert a
verdict (PHISHING / MALICIOUS / CLEAN) — redirects, drops, chains, shortener-style hops.

SAFETY: nothing actually harmful. "Malicious" == industry-standard *benign* test artifacts:
  - EICAR via secure.eicar.org (the AV test string; NOT hosted in this repo)
  - phishing / malware / unwanted via Google Safe Browsing test pages (testsafebrowsing.appspot.com)
  - "exe/file drop" == a harmless dummy file (plain-text .exe, a zip of a text file) hosted here, so the
    download path is exercised without any real executable/malware.

GitHub Pages is static: no server 30x / headers. Redirects therefore use meta-refresh + JS (what the
sandbox renders anyway). Real 30x chains would need Netlify/Cloudflare.

Usage:
    python3 threat_cases.py                       # -> ./docs/<VER>/threat + ./threat_cases.json + ./threat.properties
    python3 threat_cases.py --base https://host   # override the deploy base used in the emitted properties
    python3 threat_cases.py --out docs            # output dir (default: docs, so it deploys with the site)
"""
import argparse, io, json, os, sys, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Deploy base (GitHub Pages: https://<user>.github.io/<repo>). Used for the absolute URLs written into
# URL_SANDBOX.properties. Override with --base if a custom domain is configured.
DEFAULT_BASE = "https://commonaccount-test.github.io/UrlTestingNew"

# Cache-buster prefix — bump (t1 -> t2 ...) to force the sandbox to re-fetch instead of serving a cached verdict.
VER = "t1"
ROOT = VER + "/threat"          # path prefix under the site
FILES = ROOT + "/files"          # hosted dummy files

# ── External standard test resources ─────────────────────────────────────────────────────────────
SB_PHISH    = "https://testsafebrowsing.appspot.com/s/phishing.html"
SB_MALWARE  = "https://testsafebrowsing.appspot.com/s/malware.html"
SB_UNWANTED = "https://testsafebrowsing.appspot.com/s/unwanted.html"
EICAR       = "https://secure.eicar.org/eicar.com.txt"

PAGE_TMPL = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n"
             "{head}</head>\n<body>\n<p><strong>TEST PAGE - URL SANDBOX QA</strong> - {title}</p>\n"
             "{body}\n</body>\n</html>\n")

cases = []   # each: {id, desc, path, verdict, entry(bool)} ; entry=True -> gets a properties row

def page(path, title, body, head="", verdict=None, desc="", entry=True):
    """Register a page. `path` is extensionless under ROOT, e.g. 'phishing-redirect'."""
    full = "%s/%s.html" % (ROOT, path)
    cases.append({"id": "threat_" + path.replace("/", "_"), "desc": desc or title,
                  "path": full, "html": PAGE_TMPL.format(title=title, head=head, body=body),
                  "verdict": verdict, "entry": entry})
    return full

def meta_js_redirect(target, secs=0):
    """A meta-refresh + JS redirect to `target` (belt and suspenders for whatever the sandbox honours)."""
    head = '<meta http-equiv="refresh" content="%d;url=%s">\n' % (secs, target)
    body = ('<p>redirecting to <code>%s</code>...</p>\n'
            '<script>setTimeout(function(){location.href=%r;}, %d);</script>' % (target, target, secs * 1000))
    return head, body

def rel(path):
    """Relative link from a ROOT page to another ROOT/… path (same directory level)."""
    return os.path.basename(path)


def build():
    # ── Direct links ──────────────────────────────────────────────────────────────────────────────
    page("eicar-link", "EICAR link",
         '<p><a href="%s">Download the EICAR AV test file</a></p>' % EICAR,
         verdict="MALICIOUS", desc="anchor to the EICAR AV test file (eicar.org)")

    # ── Drops (auto-download) ───────────────────────────────────────────────────────────────────────
    head, body = meta_js_redirect(EICAR)
    page("eicar-drop", "EICAR drop", body, head=head,
         verdict="MALICIOUS", desc="auto-download EICAR from eicar.org (not hosted here)")

    exe_rel = "files/" + "benign-test.exe"
    page("exe-drop", "EXE drop",
         '<p><a href="%s" download id="d">download</a></p>\n'
         '<script>location.href=%r;</script>' % (exe_rel, exe_rel),
         verdict="MALICIOUS", desc="auto-download a benign dummy .exe (executable-extension path)")

    zip_rel = "files/" + "benign-test.zip"
    page("file-drop", "File drop",
         '<p><a href="%s" download id="d">download</a></p>\n'
         '<script>location.href=%r;</script>' % (zip_rel, zip_rel),
         verdict="CLEAN", desc="auto-download a benign .zip (generic file-download path)")

    # ── Single redirects to standard verdict pages ─────────────────────────────────────────────────
    for name, target, verdict, d in [
        ("phishing-redirect", SB_PHISH,   "PHISHING",  "meta+JS redirect to Safe Browsing phishing test page"),
        ("malware-redirect",  SB_MALWARE, "MALICIOUS", "meta+JS redirect to Safe Browsing malware test page"),
        ("unwanted-redirect", SB_UNWANTED,"PHISHING",  "meta+JS redirect to Safe Browsing unwanted-software test page"),
    ]:
        head, body = meta_js_redirect(target)
        page(name, name, body, head=head, verdict=verdict, desc=d)

    # ── Delayed JS redirect ─────────────────────────────────────────────────────────────────────────
    head, body = meta_js_redirect(SB_PHISH, secs=3)
    page("js-delayed-redirect", "JS delayed redirect", body, head=head,
         verdict="PHISHING", desc="JS redirect to phishing after a 3s delay")

    # ── Multi-hop redirect chain (5 hops) -> phishing ──────────────────────────────────────────────
    hops = 5
    for i in range(1, hops + 1):
        target = SB_PHISH if i == hops else rel("%s/multi-hop-%d.html" % (ROOT, i + 1))
        head, body = meta_js_redirect(target)
        # only the first hop is the entry we submit / assert on
        page("multi-hop-%d" % i, "Multi-redirect hop %d/%d" % (i, hops), body, head=head,
             verdict=("PHISHING" if i == 1 else None),
             desc=("5-hop redirect chain ending at phishing" if i == 1 else "chain hop %d" % i),
             entry=(i == 1))

    # ── Redirect loop (guard) A <-> B ──────────────────────────────────────────────────────────────
    head, body = meta_js_redirect(rel("%s/loop-b.html" % ROOT))
    page("loop-a", "Redirect loop A", body, head=head, verdict="CLEAN",
         desc="redirect loop A<->B (loop-guard; no threat reached)")
    head, body = meta_js_redirect(rel("%s/loop-a.html" % ROOT))
    page("loop-b", "Redirect loop B", body, head=head, entry=False, desc="loop partner")

    # ── Redirect chain that ends in an exe drop ────────────────────────────────────────────────────
    head, body = meta_js_redirect(rel("%s/exe-drop.html" % ROOT))
    page("chain-to-exe", "Chain to EXE drop", body, head=head, verdict="MALICIOUS",
         desc="redirect that ends at the exe-drop page")

    # ── Shortener-style hops (self-hosted; simulate a shortener's single redirect) ─────────────────
    for short, target, verdict, d in [
        ("s/p1", SB_PHISH, "PHISHING",  "shortener-style short path -> phishing"),
        ("s/m1", SB_MALWARE, "MALICIOUS","shortener-style short path -> malware"),
        ("s/e1", EICAR,     "MALICIOUS", "shortener-style short path -> EICAR"),
    ]:
        head, body = meta_js_redirect(target)
        page(short, "Short link " + short, body, head=head, verdict=verdict, desc=d)

    return cases


def write_file(path, content, binary=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if binary else "w"
    kw = {} if binary else {"encoding": "utf-8"}
    with open(path, mode, **kw) as fh:
        fh.write(content)
    print("  wrote", os.path.relpath(path, HERE))


def make_benign_exe():
    return (b"This is a BENIGN test file with an .exe extension for URL-sandbox QA.\r\n"
            b"It is NOT an executable and contains no code. Do not treat as malware.\r\n")


def make_benign_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", "Benign test archive for URL-sandbox QA. No payload.\n")
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE, help="deploy base for the emitted properties URLs")
    ap.add_argument("--out", default="docs", help="output dir (default: docs)")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = os.path.join(HERE, args.out)

    build()

    # .nojekyll so files (incl. .exe) are served verbatim
    write_file(os.path.join(out, ".nojekyll"), "")
    for c in cases:
        write_file(os.path.join(out, c["path"]), c["html"])
    write_file(os.path.join(out, FILES, "benign-test.exe"), make_benign_exe(), binary=True)
    write_file(os.path.join(out, FILES, "benign-test.zip"), make_benign_zip(), binary=True)

    # Record + threat index page
    write_file(os.path.join(HERE, "threat_cases.json"),
               json.dumps({"base": base, "ver": VER, "cases": cases}, indent=2))
    idx = "\n".join('<li><code>%s</code> [%s] &rarr; <a href="%s">%s</a></li>'
                    % (c["id"], c["verdict"] or "-", rel(c["path"]), c["path"])
                    for c in cases)
    write_file(os.path.join(out, ROOT, "index.html"),
               PAGE_TMPL.format(title="threat scenarios", head="",
                                body="<ul>\n" + idx + "\n</ul>"))

    # Emit URL_SANDBOX.properties blocks for the entry pages (id / url / desc / verdict).
    blocks = ["# Threat scenarios (hosted on the URL-testing site). Generated by threat_cases.py.",
              "# Verdicts are GUESSES pending a first run; artifacts are benign standard test resources.", ""]
    n = 0
    for c in cases:
        if not c.get("entry"):
            continue
        n += 1
        blocks += ["id=%s" % c["id"], "url=%s/%s" % (base, c["path"]),
                   "desc=%s" % c["desc"], "verdict=%s" % (c["verdict"] or "CLEAN"), ""]
    # Real third-party shorteners can't be minted here — leave USER placeholders to fill after creating them.
    blocks += ["# --- USER: create real short links to the pages above, then fill url= and uncomment ---",
               "#id=threat_bitly_phishing", "#url=https://bit.ly/REPLACE", "#desc=real bit.ly -> phishing-redirect",
               "#verdict=PHISHING", "",
               "#id=threat_tinyurl_eicar", "#url=https://tinyurl.com/REPLACE", "#desc=real tinyurl -> eicar-drop",
               "#verdict=MALICIOUS", ""]
    write_file(os.path.join(HERE, "threat.properties"), "\n".join(blocks) + "\n")

    print("\nDone: %d pages, %d entry cases -> threat.properties (base=%s)." % (len(cases), n, base))
    print("Deploy: commit docs/, GH Pages serves /%s/. Append threat.properties to propertyFiles/URL_SANDBOX.properties." % ROOT)


if __name__ == "__main__":
    sys.exit(main())
