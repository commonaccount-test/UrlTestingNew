#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"Screenshot blind-spot / file-drop" generator.

Every ENTRY page here renders a BENIGN-looking webpage (so a URL screenshot comes back
"clean") while the real payload is a FILE DROP or a post-capture change. This mirrors the
real finding: the sandbox screenshots the URL, sees a harmless page, and misses that the
URL also dropped a file (or only drops it later / to a real user / client-side only).

The dropped / revealed payload always points at the SINGLE known-phishing target
(t1/resolve/target.html — already made phishing), so the correct verdict is PHISHING.
A few cases drop an EICAR test marker instead -> correct verdict MALICIOUS.

If a case comes back CLEAN at the sandbox, that IS the documented gap (screenshot-only verdict).

Output: docs/t1/drop/*  + drop.properties (id/url/desc/verdict for URL_SANDBOX.properties).
Usage:  python3 drop_cases.py [--base https://host] [--out docs]

Everything here is a benign QA artifact: pages are branded TEST PAGE, payloads only link to
our own hosted phishing-target page, and the EICAR string is the standard AV test string.
"""
import argparse, os, zipfile, io

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASE = "https://commonaccount-test.github.io/UrlTestingNew"
VER = "t1"
ROOT = VER + "/drop"

# Standard AntiVirus test string (EICAR) — harmless, used only to exercise malware-drop detection.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PAGE_TMPL = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n"
             "{head}</head>\n<body>\n<p><strong>TEST PAGE - URL SANDBOX QA</strong> - {title}</p>\n"
             "{body}\n</body>\n</html>\n")

# A deliberately benign, screenshot-clean body used as the visible surface of the droppers.
BENIGN = ("<h1>Q3 Financial Report</h1>\n"
          "<p>Thank you. Your document is being prepared. No action is required.</p>\n"
          "<p>This is a routine notification from the reporting portal.</p>\n")

cases = []  # {id, path, html, verdict, entry, desc}


def add(path, body, desc, head="", verdict="PHISHING", entry=True, cid=None):
    full = "%s/%s.html" % (ROOT, path)
    cases.append({"id": "drop_" + (cid or path.replace("/", "_")), "path": full,
                  "html": PAGE_TMPL.format(title=path, head=head, body=body),
                  "verdict": verdict, "entry": entry, "desc": desc})
    return full


def raw(path, content, binary=False):
    cases.append({"id": "_raw_" + path.replace("/", "_"), "path": "%s/%s" % (ROOT, path),
                  "html": content, "verdict": "", "entry": False, "desc": "", "binary": binary})
    return "%s/%s" % (ROOT, path)


def build(base):
    PHISH = base + "/" + VER + "/resolve/target.html"   # the single known-phishing target

    # ── Payload sub-files (dropped things that carry the phishing URL) ──
    phish_html = "<html><body><p><a href=\"%s\">%s</a></p></body></html>" % (PHISH, PHISH)
    raw("payload-phish.html", phish_html)
    raw("invoice.pdf.html", phish_html)                 # double-extension payload
    raw("payload.svg", '<svg xmlns="http://www.w3.org/2000/svg"><a href="%s">'
                       '<text x="10" y="20">open</text></a>'
                       '<script>//<![CDATA[\nlocation.href="%s";\n//]]></script></svg>' % (PHISH, PHISH))
    # zip containing the phishing html
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.html", phish_html)
    raw("payload.zip", zbuf.getvalue(), binary=True)

    def anchor(href, name="report", extra=""):
        return '<a id="d" href="%s" download="%s"%s>download</a>' % (href, name, extra)

    # ============================================================
    # A. TIMING — benign render, drop fires after the screenshot window
    # ============================================================
    add("auto-download", BENIGN + anchor("payload-phish.html") +
        "<script>document.getElementById('d').click();</script>",
        "benign page auto-downloads an HTML file that contains the phishing URL")
    add("delayed-10s", BENIGN + anchor("payload-phish.html") +
        "<script>setTimeout(function(){document.getElementById('d').click();},10000);</script>",
        "clean screenshot; file drop fires at 10s (after typical capture)")
    add("delayed-30s", BENIGN + anchor("payload-phish.html") +
        "<script>setTimeout(function(){document.getElementById('d').click();},30000);</script>",
        "clean screenshot; file drop fires at 30s")
    add("countdown", BENIGN + "<p id=c>Preparing your file (5)</p>" + anchor("payload-phish.html") +
        "<script>var n=5,t=setInterval(function(){n--;document.getElementById('c').textContent="
        "'Preparing your file ('+n+')';if(n<=0){clearInterval(t);document.getElementById('d').click();}},1000);"
        "</script>",
        "fake 'preparing your file' countdown then drops the phishing file")

    # ============================================================
    # B. INTERACTION-GATED — a headless screenshot bot never interacts, so never drops
    # ============================================================
    add("on-click", BENIGN + '<button onclick="document.getElementById(\'d\').click()">View report</button>' +
        anchor("payload-phish.html"),
        "drop only when the user clicks a button (screenshot bot does not click)")
    add("on-scroll", BENIGN + "<div style='height:3000px'></div>" + anchor("payload-phish.html") +
        "<script>addEventListener('scroll',function(){document.getElementById('d').click();},{once:true});</script>",
        "drop only on scroll")
    add("on-mousemove", BENIGN + anchor("payload-phish.html") +
        "<script>addEventListener('mousemove',function(){document.getElementById('d').click();},{once:true});</script>",
        "drop only on first mouse movement")
    add("on-focus", BENIGN + anchor("payload-phish.html") +
        "<script>addEventListener('visibilitychange',function(){document.getElementById('d').click();});"
        "addEventListener('focus',function(){document.getElementById('d').click();});</script>",
        "drop only on tab focus / visibilitychange")

    # ============================================================
    # C. CLIENT-SIDE-ONLY PAYLOAD — no fetchable URL for the sandbox; screenshot benign
    # ============================================================
    add("blob-html", BENIGN +
        "<script>var h='<html><body><a href=\\'" + PHISH + "\\'>" + PHISH + "</a></body></html>';"
        "var b=new Blob([h],{type:'text/html'});var a=document.createElement('a');"
        "a.href=URL.createObjectURL(b);a.download='report.html';a.click();</script>",
        "payload HTML built client-side as a Blob (no URL to fetch) — phishing link inside")
    add("blob-eicar", BENIGN +
        "<script>var b=new Blob(['" + EICAR + "'],{type:'application/octet-stream'});"
        "var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='report.com';a.click();</script>",
        "EICAR test marker dropped via client-side Blob — malware-drop vs clean screenshot", verdict="MALICIOUS")
    add("data-uri-download", BENIGN +
        "<script>var p='<html><body><a href=\\'" + PHISH + "\\'>x</a></body></html>';"
        "var a=document.createElement('a');a.href='data:text/html;base64,'+btoa(p);"
        "a.download='report.html';a.click();</script>",
        "payload delivered as a base64 data: URI download (phishing link inside)")
    add("js-decoded", BENIGN +
        "<script>var u=atob('" + _b64(PHISH) + "');var h='<a href=\"'+u+'\">x</a>';"
        "var b=new Blob([h],{type:'text/html'});var a=document.createElement('a');"
        "a.href=URL.createObjectURL(b);a.download='report.html';a.click();</script>",
        "phishing URL base64-decoded in JS then dropped (static HTML has no URL)")

    # ============================================================
    # D. CLOAKING — benign to the headless/screenshot bot, drop to a real user
    # ============================================================
    add("cloak-webdriver", BENIGN + anchor("payload-phish.html") +
        "<script>if(!navigator.webdriver){document.getElementById('d').click();}</script>",
        "serves benign to navigator.webdriver (screenshot bot); drops phishing to a real browser")
    add("cloak-headless-ua", BENIGN + anchor("payload-phish.html") +
        "<script>if(!/Headless|PhantomJS|bot|crawler/i.test(navigator.userAgent))"
        "{document.getElementById('d').click();}</script>",
        "serves benign to headless/bot user-agents; drops phishing otherwise")
    add("cloak-interaction", BENIGN + "<div style='height:2000px'></div>" + anchor("payload-phish.html") +
        "<script>var m=false,s=false;addEventListener('mousemove',function(){m=true;f();});"
        "addEventListener('scroll',function(){s=true;f();});function f(){if(m&&s)"
        "document.getElementById('d').click();}</script>",
        "only drops after BOTH real mousemove and scroll (no interaction -> benign)")

    # ============================================================
    # E. DUAL NATURE — one URL is a viewable benign site AND a dropper / swapper
    # ============================================================
    add("dual-benign-site",
        "<header><h1>Acme Reports Portal</h1></header>"
        "<main><p>Welcome. Browse your available reports below.</p>"
        "<ul><li>Q1 summary</li><li>Q2 summary</li><li>Q3 summary</li></ul></main>" +
        anchor("payload-phish.html") +
        "<script>document.getElementById('d').click();</script>",
        "renders a full benign-looking portal (clean screenshot) AND silently drops phishing file")
    add("dual-decoy-login",
        "<h2>Demo Login (test)</h2><form onsubmit='return false'>"
        "<input placeholder='user'><input type=password placeholder='pass'>"
        "<button>Sign in</button></form>" + anchor("payload-phish.html") +
        "<script>document.getElementById('d').click();</script>",
        "harmless demo login form (benign screenshot) while dropping the phishing file")
    add("render-then-swap", BENIGN +
        "<script>setTimeout(function(){document.body.innerHTML="
        "'<a href=\"" + PHISH + "\">" + PHISH + "</a>';},12000);</script>",
        "renders benign, then swaps the DOM to the phishing link after the capture window")

    # ============================================================
    # F. CROSS-MEDIUM DROP — the dropped FILE itself carries the phishing URL
    # ============================================================
    add("drops-pdf", BENIGN + anchor("../drop/dropped.pdf", "report.pdf") +
        "<script>document.getElementById('d').click();</script>",
        "benign page drops a PDF that contains the phishing URL",
        cid="drops-pdf")
    add("drops-docx", BENIGN + anchor("../drop/dropped.docx", "report.docx") +
        "<script>document.getElementById('d').click();</script>",
        "benign page drops a DOCX that contains the phishing URL",
        cid="drops-docx")
    add("drops-zip", BENIGN + anchor("payload.zip", "report.zip") +
        "<script>document.getElementById('d').click();</script>",
        "benign page drops a ZIP containing a phishing HTML")
    add("drops-svg", BENIGN + anchor("payload.svg", "report.svg") +
        "<script>document.getElementById('d').click();</script>",
        "benign page drops an SVG that scripts/anchors to the phishing URL")
    add("drops-double-ext", BENIGN + anchor("invoice.pdf.html", "invoice.pdf") +
        "<script>document.getElementById('d').click();</script>",
        "benign page drops invoice.pdf.html (double extension) carrying the phishing URL")

    # ============================================================
    # G. BOTH payloads at once — does catching one mask the other?
    # ============================================================
    add("phish-and-drop",
        "<p>Download your statement:</p><p><a href=\"" + PHISH + "\">" + PHISH + "</a></p>" +
        "<script>var b=new Blob(['" + EICAR + "'],{type:'application/octet-stream'});"
        "var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='stmt.com';a.click();</script>",
        "renders a visible phishing link AND drops an EICAR marker (two mediums in one URL)",
        verdict="MALICIOUS")


def _b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()


def write_file(path, content, binary=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if binary else "w"
    with open(path, mode) as fh:
        fh.write(content if binary else content)
        if not binary:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--out", default="docs")
    ap.add_argument("--nonce", default="",
                    help="append ?v=<nonce> to each case URL so its sha256 changes (forces a fresh sandbox scan)")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = os.path.join(HERE, args.out)
    q = ("?v=" + args.nonce) if args.nonce else ""

    build(base)
    write_file(os.path.join(out, ".nojekyll"), "")
    for c in cases:
        p = os.path.join(out, c["path"])
        if c.get("binary"):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(c["html"])
        else:
            write_file(p, c["html"])

    # index
    entries = [c for c in cases if c.get("entry")]
    idx = "\n".join('<li><code>%s</code> [%s] -> <a href="%s">%s</a> — %s</li>'
                    % (c["id"], c["verdict"], os.path.basename(c["path"]), c["path"], c["desc"])
                    for c in entries)
    write_file(os.path.join(out, ROOT, "index.html"),
               PAGE_TMPL.format(title="drop / screenshot-blind-spot", head="", body="<ul>\n" + idx + "\n</ul>"))

    # properties block
    lines = ["# >>> DROP BEGIN",
             "# Screenshot-blind-spot / file-drop cases (generated by drop_cases.py).",
             "# Each ENTRY page renders a benign webpage (clean screenshot) but drops/reveals a payload.",
             "# PHISHING payloads link to %s/%s/resolve/target.html (make it phishing)." % (base, VER),
             "# A sandbox verdict of CLEAN on any of these = the screenshot-only blind spot.", ""]
    for c in entries:
        lines += ["id=%s" % c["id"], "url=%s/%s%s" % (base, c["path"], q),
                  "desc=%s" % c["desc"], "verdict=%s" % c["verdict"], ""]
    lines.append("# <<< DROP END")
    write_file(os.path.join(HERE, "drop.properties"), "\n".join(lines) + "\n")

    print("PHISH target (make phishing): %s/%s/resolve/target.html" % (base, VER))
    print("pages: %d | entry cases: %d -> drop.properties" % (len(cases), len(entries)))


if __name__ == "__main__":
    main()
