#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive threat-scenario generator for the URL-sandbox VERDICT engine (SEPARATE from
build_cases.py / generate.py, which cover URL *extraction*). Goal: cover the entire sandbox engine —
every dimension in URL_Sandboxing_Instructions.md that can be exercised with a real URL.

Three kinds of case:
  GH   — a page hosted here that the sandbox fetches/renders (redirects, drops, phishing sims, SVG,
         scheme abuse, obfuscation, scale). Deploys under docs/<VER>/threat/.
  REAL — a real public standard resource used directly as the submitted URL (httpbin real 30x/status/
         delay, badssl TLS errors, eicar.org files, neverssl, IP/host forms, SSRF/internal, NXDOMAIN,
         timeout, safe sites). No page hosted; the URL goes straight into the properties.
  USER — needs manual setup (admin policy, channels, API/imports, allow/blocklist, notifications, edit
         history, real URL shorteners, attachments, click-time switch, a11y). Emitted commented-out so
         the coverage is documented even though it can't be auto-run.

SAFETY: nothing actually harmful. "Malicious" == industry-standard *benign* test artifacts (EICAR via
secure.eicar.org — never hosted here; Google Safe Browsing test pages; benign dummy exe/zip). Fake login
pages are labelled TEST PAGE and never submit (action="#", onsubmit return false). Script payloads only
alert('<TEST-ID>'). GitHub Pages is static: redirects use meta-refresh + JS.

Usage:
    python3 threat_cases.py                       # -> docs/<VER>/threat + threat_cases.json + threat.properties
    python3 threat_cases.py --base https://host   # override deploy base used in the emitted properties
    python3 threat_cases.py --out docs            # output dir (default: docs)
"""
import argparse, io, json, os, sys, zipfile
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASE = "https://commonaccount-test.github.io/UrlTestingNew"

# Cache-buster prefix — bump (t1 -> t2 ...) to force the sandbox to re-fetch instead of serving a cached verdict.
VER = "t1"
ROOT = VER + "/threat"
FILES = ROOT + "/files"

# ── External standard test resources ──────────────────────────────────────────────────────────────
SB_PHISH    = "https://testsafebrowsing.appspot.com/s/phishing.html"
SB_MALWARE  = "https://testsafebrowsing.appspot.com/s/malware.html"
SB_UNWANTED = "https://testsafebrowsing.appspot.com/s/unwanted.html"
EICAR       = "https://secure.eicar.org/eicar.com.txt"
QR_API      = "https://api.qrserver.com/v1/create-qr-code/?size=240x240&data="

PAGE_TMPL = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n"
             "{head}</head>\n<body>\n<p><strong>TEST PAGE - URL SANDBOX QA</strong> - {title}</p>\n"
             "{body}\n</body>\n</html>\n")

cases = []      # GH pages
real  = []      # REAL external URL cases: (id, url, desc, verdict)
user  = []      # USER manual cases: (id, urlHint, desc, verdict)

def page(path, title, body, head="", verdict=None, desc="", entry=True, entry_query=""):
    full = "%s/%s.html" % (ROOT, path)
    cases.append({"id": "threat_" + path.replace("/", "_"), "desc": desc or title,
                  "path": full, "html": PAGE_TMPL.format(title=title, head=head, body=body),
                  "verdict": verdict, "entry": entry, "entry_query": entry_query})
    return full

def meta_js_redirect(target, secs=0):
    head = '<meta http-equiv="refresh" content="%d;url=%s">\n' % (secs, target)
    body = ('<p>redirecting to <code>%s</code>...</p>\n'
            '<script>setTimeout(function(){location.href=%r;}, %d);</script>' % (target, target, secs * 1000))
    return head, body

def bn(path):
    return os.path.basename(path)

def R(cid, url, desc, verdict):
    real.append((cid, url, desc, verdict))

def U(cid, hint, desc, verdict):
    user.append((cid, hint, desc, verdict))


def build():
    # ═══ A. Direct malicious links (GH) ═════════════════════════════════════════════════════════════
    page("eicar-link", "EICAR link", '<p><a href="%s">EICAR AV test file</a></p>' % EICAR,
         verdict="MALICIOUS", desc="anchor to the EICAR AV test file")
    page("phishing-link", "Phishing link", '<p><a href="%s">login</a></p>' % SB_PHISH,
         verdict="PHISHING", desc="anchor to Safe Browsing phishing test page")
    page("malware-link", "Malware link", '<p><a href="%s">file</a></p>' % SB_MALWARE,
         verdict="MALICIOUS", desc="anchor to Safe Browsing malware test page")

    # ═══ B. Drops / downloads (GH, benign dummies + eicar via eicar.org) ═════════════════════════════
    head, body = meta_js_redirect(EICAR)
    page("eicar-drop", "EICAR drop", body, head=head, verdict="MALICIOUS", desc="auto-download EICAR")
    for ext, verdict, d in [("exe", "MALICIOUS", "executable"), ("scr", "MALICIOUS", "screensaver exe"),
                            ("bat", "MALICIOUS", "batch script"), ("js", "MALICIOUS", "JS dropper"),
                            ("jar", "MALICIOUS", "java archive"), ("msi", "MALICIOUS", "installer")]:
        f = "files/benign-test.%s" % ext
        page("drop-%s" % ext, "Drop .%s" % ext,
             '<p><a href="%s" download>download</a></p>\n<script>location.href=%r;</script>' % (f, f),
             verdict=verdict, desc="auto-download benign dummy .%s (%s path)" % (ext, d))
    page("drop-double-ext", "Double extension drop",
         '<p><a href="files/invoice.pdf.exe" download>invoice.pdf</a></p>\n'
         '<script>location.href="files/invoice.pdf.exe";</script>',
         verdict="MALICIOUS", desc="double-extension invoice.pdf.exe")
    page("file-drop", "Benign file drop",
         '<p><a href="files/benign-test.zip" download>download</a></p>\n'
         '<script>location.href="files/benign-test.zip";</script>',
         verdict="CLEAN", desc="auto-download a benign .zip")
    page("archive-pwd", "Password archive drop",
         '<p>password: <code>infected</code></p>\n<p><a href="files/protected.zip" download>archive</a></p>\n'
         '<script>location.href="files/protected.zip";</script>',
         verdict="MALICIOUS", desc="password-protected archive (per policy, often held)")

    # ═══ C. Redirects / navigation (GH, meta+JS) ════════════════════════════════════════════════════
    for name, target, verdict, d in [
        ("phishing-redirect", SB_PHISH,   "PHISHING",  "meta+JS redirect to phishing"),
        ("malware-redirect",  SB_MALWARE, "MALICIOUS", "meta+JS redirect to malware"),
        ("unwanted-redirect", SB_UNWANTED,"PHISHING",  "meta+JS redirect to unwanted-software"),
        ("benign-redirect",   "https://example.com/", "CLEAN", "meta+JS redirect to a benign site"),
    ]:
        head, body = meta_js_redirect(target)
        page(name, name, body, head=head, verdict=verdict, desc=d)
    head, body = meta_js_redirect(SB_PHISH, secs=3)
    page("js-delayed-redirect", "JS delayed redirect", body, head=head, verdict="PHISHING",
         desc="JS redirect to phishing after 3s")
    page("js-replace-redirect", "JS location.replace",
         '<script>location.replace(%r);</script>' % SB_PHISH, verdict="PHISHING",
         desc="location.replace() redirect to phishing")
    page("form-autosubmit-redirect", "Auto-submit form",
         '<form id="f" action="%s" method="get"></form>\n<script>document.getElementById("f").submit();</script>' % SB_PHISH,
         verdict="PHISHING", desc="auto-submitting form navigating to phishing")
    page("anchor-autoclick-redirect", "Anchor auto-click",
         '<a id="a" href="%s">go</a>\n<script>document.getElementById("a").click();</script>' % SB_PHISH,
         verdict="PHISHING", desc="auto-clicked anchor to phishing")
    page("base-href-redirect", "base-href redirect",
         '<base href="https://testsafebrowsing.appspot.com/s/">\n<meta http-equiv="refresh" content="0;url=phishing.html">',
         verdict="PHISHING", desc="meta-refresh resolved via <base href> to phishing")

    # Multi-hop chain (5) -> phishing
    hops = 5
    for i in range(1, hops + 1):
        target = SB_PHISH if i == hops else bn("%s/multi-hop-%d.html" % (ROOT, i + 1))
        head, body = meta_js_redirect(target)
        page("multi-hop-%d" % i, "Multi-redirect hop %d/%d" % (i, hops), body, head=head,
             verdict=("PHISHING" if i == 1 else None),
             desc=("5-hop chain ending at phishing" if i == 1 else "chain hop %d" % i), entry=(i == 1))
    # Loop A<->B (guard)
    head, body = meta_js_redirect(bn("%s/loop-b.html" % ROOT))
    page("loop-a", "Redirect loop A", body, head=head, verdict="CLEAN", desc="redirect loop guard A<->B")
    head, body = meta_js_redirect(bn("%s/loop-a.html" % ROOT))
    page("loop-b", "Redirect loop B", body, head=head, entry=False, desc="loop partner")
    # Chain -> exe drop
    head, body = meta_js_redirect(bn("%s/drop-exe.html" % ROOT))
    page("chain-to-exe", "Chain to EXE drop", body, head=head, verdict="MALICIOUS", desc="redirect ending at exe drop")
    # Open-redirect style (?url=)
    page("open-redirect", "Open redirect (?url=)",
         '<script>var u=new URLSearchParams(location.search).get("url");if(u)location.href=u;</script>'
         '<p>?url= open redirect</p>', verdict="PHISHING",
         desc="open-redirect: entry URL carries ?url=<phishing>",
         entry_query="?url=" + quote(SB_PHISH, safe=""))

    # ═══ D. SSRF / internal targets via redirect (GH) — sandbox must NOT fetch these ════════════════
    for name, target, d in [
        ("ssrf-localhost",  "http://127.0.0.1/",                         "redirect to loopback"),
        ("ssrf-localhost2", "http://localhost/",                         "redirect to localhost"),
        ("ssrf-metadata",   "http://169.254.169.254/latest/meta-data/",  "redirect to cloud metadata"),
        ("ssrf-private10",  "http://10.0.0.1/",                          "redirect to 10.x private"),
        ("ssrf-private192", "http://192.168.1.1/",                       "redirect to 192.168.x private"),
    ]:
        head, body = meta_js_redirect(target)
        page(name, name, body, head=head, verdict="CLEAN", desc=d + " (must-not-SSRF; expect no fetch)")

    # ═══ E. Content sims — phishing/credential (GH, labelled, non-submitting) ════════════════════════
    def login_form(title, brand):
        return ('<h2>%s</h2>\n<form action="#" onsubmit="return false">\n'
                'Email <input name="u"><br>Password <input type="password" name="p"><br>'
                '<button>Sign in</button>\n</form>' % brand)
    page("fake-login", "Fake login", login_form("Fake login", "Sign in to your account"),
         verdict="PHISHING", desc="generic fake login form (non-submitting)")
    page("fake-bank-login", "Fake bank login", login_form("Bank", "SecureBank Online Banking"),
         verdict="PHISHING", desc="brand-spoof bank login")
    page("oauth-consent", "OAuth consent phishing",
         '<h2>Grant access</h2><p>App requests access to your mailbox.</p>'
         '<form action="#" onsubmit="return false"><button>Allow</button></form>',
         verdict="PHISHING", desc="OAuth consent phishing simulation")
    page("clickfix-captcha", "ClickFix fake captcha",
         '<h2>Verify you are human</h2><p>Press Win+R and paste to continue.</p>'
         '<button onclick="return false">I am not a robot</button>',
         verdict="PHISHING", desc="ClickFix / fake-captcha social engineering")
    page("cred-form-webhook", "Credential form",
         '<form action="#" onsubmit="return false">card <input name="c"><button>Pay</button></form>',
         verdict="PHISHING", desc="credential/card form (webhook exfil sim, non-submitting)")
    page("homoglyph-brand", "Homoglyph brand",
         '<h2>Sign in to аpple.com</h2>' + login_form("", ""),  # Cyrillic а
         verdict="PHISHING", desc="homoglyph brand text in a login page")

    # ═══ F. SVG (GH) ════════════════════════════════════════════════════════════════════════════════
    page("svg-with-script", "SVG with script",
         '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("SVG-TEST")</script>'
         '<a href="%s"><text x="10" y="20">x</text></a></svg>' % SB_PHISH,
         verdict="PHISHING", desc="inline SVG carrying a script + link to phishing")

    # ═══ G. Scheme abuse (GH anchors) — expect blocked/ignored ══════════════════════════════════════
    for name, href, d in [
        ("scheme-javascript", "javascript:alert('SCHEME-TEST')", "javascript: URI"),
        ("scheme-data",       "data:text/html,<script>alert('SCHEME-TEST')</script>", "data:text/html URI"),
        ("scheme-vbscript",   "vbscript:msgbox('x')", "vbscript: URI"),
        ("scheme-file",       "file:///etc/passwd", "file: URI"),
        ("scheme-blob",       "blob:https://example.com/uuid", "blob: URI"),
    ]:
        page(name, name, '<p><a href="%s">click</a></p>' % href, verdict="CLEAN",
             desc="blocked-scheme anchor: %s (expect ignored/blocked)" % d)

    # ═══ H. Obfuscation (GH anchors to a phishing target) ═══════════════════════════════════════════
    enc = quote(SB_PHISH, safe="")
    page("obf-percent", "Percent-encoded URL", '<a href="%s">x</a>' % enc, verdict="PHISHING",
         desc="percent-encoded phishing URL in href")
    page("obf-double", "Double-encoded URL", '<a href="%s">x</a>' % quote(enc, safe=""), verdict="PHISHING",
         desc="double percent-encoded phishing URL")
    page("obf-mixedcase", "Mixed-case scheme",
         '<a href="HtTpS://testsafebrowsing.appspot.com/s/phishing.html">x</a>', verdict="PHISHING",
         desc="mixed-case scheme")
    page("obf-userinfo", "Userinfo trick",
         '<a href="https://example.com@testsafebrowsing.appspot.com/s/phishing.html">example.com</a>',
         verdict="PHISHING", desc="userinfo trick good.com@evil.com (real host is phishing)")
    page("obf-zerowidth", "Zero-width in URL",
         '<a href="https://testsafebrowsing.appspot.com/s/phish​ing.html">x</a>', verdict="PHISHING",
         desc="zero-width char inside the URL")
    page("obf-split", "URL split by tags",
         'https://testsafebrowsing<span>.appspot.com</span>/s/phishing.html', verdict="PHISHING",
         desc="URL split across HTML tags")

    # ═══ I. QR (GH — image encodes a phishing URL) ══════════════════════════════════════════════════
    page("qr-phishing", "QR to phishing", '<img src="%s%s" alt="qr">' % (QR_API, quote(SB_PHISH, safe="")),
         verdict="PHISHING", desc="QR image encoding a phishing URL (quishing)")

    # ═══ J. Scale / limits (GH) ═════════════════════════════════════════════════════════════════════
    many = "\n".join('<a href="https://example.com/link%d">l%d</a>' % (i, i) for i in range(1, 121))
    page("scale-100-links", "100+ links", many + '\n<a href="%s">p</a>' % SB_PHISH, verdict="PHISHING",
         desc="120 links + one phishing (bulk handling)")
    longurl = "https://testsafebrowsing.appspot.com/s/phishing.html?x=" + ("a" * 2500)
    page("scale-long-url", "Very long URL", '<a href="%s">x</a>' % longurl, verdict="PHISHING",
         desc=">2000-char URL to phishing")

    # ═══ K. Shortener-style self-hosted hops (GH) ═══════════════════════════════════════════════════
    for short, target, verdict, d in [
        ("s/p1", SB_PHISH, "PHISHING", "short path -> phishing"),
        ("s/m1", SB_MALWARE, "MALICIOUS", "short path -> malware"),
        ("s/e1", EICAR, "MALICIOUS", "short path -> EICAR"),
    ]:
        head, body = meta_js_redirect(target)
        page(short, "Short link " + short, body, head=head, verdict=verdict, desc=d)

    # ═══ L. Click-time switch (GH, manual flip) ─ host benign now, flip to malicious later ══════════
    page("switch", "Click-time switch", '<p>Currently benign. Flip this page to a redirect to phishing '
         'after delivery to test time-of-click re-scan.</p>', verdict="CLEAN", entry=False,
         desc="time-of-click: benign at delivery; edit later (USER)")

    # ═══════════════════════════ REAL external standard resources ═══════════════════════════════════
    # httpbin — real 30x / status / delay / auth (what GitHub Pages cannot do)
    R("real_httpbin_redir5",  "https://httpbin.org/redirect/5",  "real 5-hop 30x chain (benign end)", "CLEAN")
    R("real_httpbin_redir20", "https://httpbin.org/redirect/20", "real 20-hop 30x chain (guard)", "CLEAN")
    R("real_httpbin_to_phish","https://httpbin.org/redirect-to?url=" + SB_PHISH, "real 30x -> phishing", "PHISHING")
    R("real_httpbin_to_eicar","https://httpbin.org/redirect-to?url=" + EICAR,   "real 30x -> EICAR", "MALICIOUS")
    R("real_httpbin_404",     "https://httpbin.org/status/404",  "HTTP 404", "CLEAN")
    R("real_httpbin_500",     "https://httpbin.org/status/500",  "HTTP 500", "CLEAN")
    R("real_httpbin_delay",   "https://httpbin.org/delay/10",    "slow response (10s)", "CLEAN")
    R("real_httpbin_auth",    "https://httpbin.org/basic-auth/user/passwd", "basic-auth challenge", "CLEAN")
    # badssl — TLS anomalies
    for h, d in [("expired", "expired cert"), ("self-signed", "self-signed cert"),
                 ("wrong.host", "wrong-host cert"), ("untrusted-root", "untrusted root"),
                 ("revoked", "revoked cert"), ("no-common-name", "no CN"), ("mixed-script", "mixed-script host")]:
        R("real_badssl_" + h.replace(".", "_"), "https://%s.badssl.com/" % h, "TLS: " + d, "CLEAN")
    R("real_badssl_httpbin_mixed", "https://mixed.badssl.com/", "mixed active content", "CLEAN")
    R("real_plain_http", "http://neverssl.com/", "plain HTTP (no TLS)", "CLEAN")
    # eicar variants
    for f in ["eicar.com", "eicar.com.txt", "eicar_com.zip", "eicarcom2.zip"]:
        R("real_eicar_" + f.replace(".", "_"), "https://secure.eicar.org/" + f, "EICAR file " + f, "MALICIOUS")
    # safe baselines
    R("real_safe_example", "https://example.com/", "benign site", "CLEAN")
    R("real_safe_iana",    "https://www.iana.org/", "benign site", "CLEAN")
    # host/IP representation forms (example.com == 93.184.216.34)
    R("real_ip_v4",     "http://93.184.216.34/", "IPv4 literal", "CLEAN")
    R("real_ip_dotless","http://1573804850/",    "dotless decimal IP", "CLEAN")
    R("real_ip_hex",    "http://0x5db8d822/",     "hex IP", "CLEAN")
    R("real_ip_v6",     "http://[2606:2800:220:1:248:1893:25c8:1946]/", "IPv6 literal", "CLEAN")
    R("real_userinfo",  "https://example.com@testsafebrowsing.appspot.com/s/phishing.html",
      "userinfo trick real host=phishing", "PHISHING")
    R("real_idn_puny",  "https://xn--80ak6aa92e.com/", "punycode/IDN host", "CLEAN")
    # errors
    R("real_nxdomain",  "http://nonexistent.invalid/", "non-resolving domain", "CLEAN")
    R("real_timeout",   "http://10.255.255.1/",        "connection timeout", "CLEAN")
    # SSRF / internal as the submitted URL directly
    R("real_ssrf_loopback", "http://127.0.0.1/", "loopback (must-not-fetch)", "CLEAN")
    R("real_ssrf_metadata", "http://169.254.169.254/latest/meta-data/", "cloud metadata (must-not-fetch)", "CLEAN")

    # ═══════════════════════════ USER — manual setup (documented, not auto-run) ══════════════════════
    U("user_shortener_bitly",  "https://bit.ly/REPLACE",     "real bit.ly -> phishing-redirect", "PHISHING")
    U("user_shortener_tinyurl","https://tinyurl.com/REPLACE","real tinyurl -> eicar-drop", "MALICIOUS")
    U("user_shortener_tco",    "https://t.co/REPLACE",       "real t.co -> malware-redirect", "MALICIOUS")
    U("user_clicktime_switch", "%BASE%/" + ROOT + "/switch.html",
      "deliver switch.html benign, then flip it to a phishing redirect and re-check", "PHISHING")
    U("user_attach_pdf_link",  "%BASE%/" + ROOT + "/files/link.pdf", "PDF attachment with an embedded phishing link", "PHISHING")
    U("user_attach_docx_link", "%BASE%/" + ROOT + "/files/link.docx", "DOCX attachment with an embedded phishing link", "PHISHING")
    U("user_admin_policy_off", "n/a", "feature off per-org: URL must pass through unsandboxed", "CLEAN")
    U("user_allowlist_exact",  "n/a", "allowlisted domain must bypass sandbox", "CLEAN")
    U("user_blocklist_sub",    "n/a", "blocklisted subdomain must be blocked", "PHISHING")
    U("user_channel_mobile",   "n/a", "same URL via mobile app must be sandboxed identically", "PHISHING")
    U("user_api_created",      "n/a", "content created via API/import must be sandboxed", "PHISHING")
    U("user_notification",     "n/a", "URL in digest/push notification must be sandboxed", "PHISHING")
    U("user_cache_expiry",     "n/a", "URL flagged later must be blocked despite earlier allow", "PHISHING")
    return cases


def write_file(path, content, binary=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as fh:
        fh.write(content)


def make_benign_exe():
    return (b"BENIGN test file with an executable extension for URL-sandbox QA.\r\n"
            b"Not an executable; no code. Do not treat as malware.\r\n")

def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--out", default="docs")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = os.path.join(HERE, args.out)

    build()

    write_file(os.path.join(out, ".nojekyll"), "")
    for c in cases:
        write_file(os.path.join(out, c["path"]), c["html"])
    # benign dummy files (exe extensions all share the same harmless bytes)
    stub = make_benign_exe()
    for ext in ["exe", "scr", "bat", "js", "jar", "msi"]:
        write_file(os.path.join(out, FILES, "benign-test.%s" % ext), stub, binary=True)
    write_file(os.path.join(out, FILES, "invoice.pdf.exe"), stub, binary=True)
    write_file(os.path.join(out, FILES, "benign-test.zip"), make_zip({"README.txt": "benign\n"}), binary=True)
    # "password-protected" placeholder (real pwd-zip needs a tool; benign stub documents intent)
    write_file(os.path.join(out, FILES, "protected.zip"), make_zip({"NOTE.txt": "benign placeholder; replace with a real pwd-zip if needed\n"}), binary=True)

    # threat index
    idx = "\n".join('<li><code>%s</code> [%s] &rarr; <a href="%s">%s</a></li>'
                    % (c["id"], c["verdict"] or "-", bn(c["path"]), c["path"]) for c in cases)
    write_file(os.path.join(out, ROOT, "index.html"), PAGE_TMPL.format(title="threat scenarios", head="", body="<ul>\n" + idx + "\n</ul>"))

    write_file(os.path.join(HERE, "threat_cases.json"),
               json.dumps({"base": base, "ver": VER, "gh": cases, "real": real, "user": user}, indent=2))

    # ── Emit URL_SANDBOX.properties blocks ──────────────────────────────────────────────────────────
    out_lines = ["# Threat scenarios — generated by threat_cases.py. Verdicts are GUESSES pending a run.",
                 "# GH = hosted here; REAL = public standard resource; USER = manual setup (commented).", ""]
    nGH = nR = 0
    out_lines.append("# ── GH: hosted pages ──")
    for c in cases:
        if not c.get("entry"):
            continue
        nGH += 1
        out_lines += ["id=%s" % c["id"], "url=%s/%s%s" % (base, c["path"], c.get("entry_query", "")),
                      "desc=%s" % c["desc"], "verdict=%s" % (c["verdict"] or "CLEAN"), ""]
    out_lines.append("# ── REAL: public standard resources ──")
    for cid, url, desc, verdict in real:
        nR += 1
        out_lines += ["id=%s" % cid, "url=%s" % url, "desc=%s" % desc, "verdict=%s" % verdict, ""]
    out_lines.append("# ── USER: manual setup (fill url= / configure, then uncomment) ──")
    for cid, hint, desc, verdict in user:
        out_lines += ["#id=%s" % cid, "#url=%s" % hint.replace("%BASE%", base),
                      "#desc=%s" % desc, "#verdict=%s" % verdict, ""]
    write_file(os.path.join(HERE, "threat.properties"), "\n".join(out_lines) + "\n")

    print("Pages: %d | GH entries: %d | REAL: %d | USER: %d" % (len(cases), nGH, nR, len(user)))
    print("Deploy docs/, then append threat.properties to propertyFiles/URL_SANDBOX.properties.")


if __name__ == "__main__":
    sys.exit(main())
