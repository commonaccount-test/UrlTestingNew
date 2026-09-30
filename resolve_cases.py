#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"Resolves-to-one-target" generator. Every page here references a URL — relative, root-relative,
protocol-relative, via <base href>, meta-refresh, JS, or an auto-loading attribute — that RESOLVES to a
SINGLE hosted target page. Make that ONE target phishing and every wrapper mail should get quarantined
(the sandbox must fetch the wrapper, resolve the inner reference to the target, and evaluate the target).

The mail links to a wrapper page (the entry URL). Expected verdict: PHISHING (resolves to the target).

Output: docs/t1/resolve/*  + resolve.properties (id/url/desc/verdict for URL_SANDBOX.properties).
Usage: python3 resolve_cases.py [--base https://host] [--out docs]
"""
import argparse, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASE = "https://commonaccount-test.github.io/UrlTestingNew"
VER = "t1"
ROOT = VER + "/resolve"

PAGE_TMPL = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n"
             "{head}</head>\n<body>\n<p><strong>TEST PAGE - URL SANDBOX QA</strong> - {title}</p>\n"
             "{body}\n</body>\n</html>\n")

cases = []   # {id, path, html, verdict, entry, desc}

def page(path, body, desc, head="", verdict="PHISHING", entry=True):
    full = "%s/%s.html" % (ROOT, path)
    cases.append({"id": "resolve_" + path.replace("/", "_"), "path": full,
                  "html": PAGE_TMPL.format(title=path, head=head, body=body),
                  "verdict": verdict, "entry": entry, "desc": desc})
    return full

def meta(url, secs=0):
    return '<meta http-equiv="refresh" content="%d;url=%s">\n' % (secs, url)


def build(base):
    rest = base.split("://", 1)[1]
    host = rest.split("/", 1)[0]
    repo = "/" + rest.split("/", 1)[1] if "/" in rest else ""
    TARGET   = base + "/" + ROOT + "/target.html"           # absolute
    ROOTREL  = (repo + "/" + ROOT + "/target.html")          # /UrlTestingNew/t1/resolve/target.html
    PROTREL  = "//" + host + repo + "/" + ROOT + "/target.html"

    # ── The single target everything resolves to (MAKE THIS PHISHING) ──
    page("target",
         "<h2>Sign in to your account</h2>\n<form action=\"#\" onsubmit=\"return false\">\n"
         "Email <input name=\"u\"><br>Password <input type=\"password\" name=\"p\"><br>"
         "<button>Sign in</button>\n</form>",
         "THE single resolve target — make this URL phishing")

    # ── Anchor forms of the same target ──
    page("abs-href",          '<a href="%s">link</a>' % TARGET,        "absolute href -> target")
    page("rel-samedir",       '<a href="target.html">link</a>',        "same-dir relative href -> target")
    page("rel-dotslash",      '<a href="./target.html">link</a>',      "./ relative href -> target")
    page("root-relative",     '<a href="%s">link</a>' % ROOTREL,       "root-relative href -> target")
    page("protocol-relative", '<a href="%s">link</a>' % PROTREL,       "protocol-relative //host href -> target")
    page("deep-dotsegments",  '<a href="a/b/../../target.html">link</a>', "dot-segment collapse a/b/../../ -> target")
    page("encoded-dot",       '<a href="%2e/target.html">link</a>',    "percent-encoded ./ (%2e) -> target")
    page("backslash-rel",     '<a href=".\\target.html">link</a>',     "backslash relative -> target")
    page("anchor-query",      '<a href="target.html?src=mail">link</a>',   "relative + query -> target")
    page("anchor-fragment",   '<a href="target.html#section">link</a>',    "relative + fragment -> target")

    # ── <base href> changes how relatives resolve ──
    page("base-href-rel", '<a href="target.html">link</a>',
         "<base href> + relative -> target", head='<base href="%s/%s/">\n' % (base, ROOT))
    page("base-href-only-path", '<a href="target.html">link</a>',
         "<base href> (path only) + relative -> target", head='<base href="%s/">\n' % (repo.lstrip("/") and (repo + "/" + ROOT + "/") or (ROOT + "/")))

    # ── meta refresh (relative / parent) ──
    page("meta-refresh-rel", "redirecting...", "meta-refresh relative -> target", head=meta("target.html"))
    page("meta-refresh-dotslash", "redirecting...", "meta-refresh ./ -> target", head=meta("./target.html"))
    page("sub/meta-refresh-parent", "redirecting...", "meta-refresh ../ from subdir -> target", head=meta("../target.html"))

    # ── JS navigation (relative) ──
    page("js-href-rel",    '<script>location.href="target.html";</script>',    "JS location.href relative -> target")
    page("js-assign-rel",  '<script>location.assign("./target.html");</script>',"JS location.assign relative -> target")
    page("js-replace-rel", '<script>location.replace("target.html");</script>', "JS location.replace relative -> target")

    # ── Auto-loading attributes (relative) — resolve to the target ──
    page("img-rel",     '<img src="target.html">',                 "img src relative -> target")
    page("iframe-rel",  '<iframe src="target.html"></iframe>',      "iframe src relative -> target")
    page("form-rel",    '<form action="target.html"><input name="x"></form>', "form action relative -> target")
    page("link-rel",    '<link rel="stylesheet" href="target.html">', "link href relative -> target")
    page("script-rel",  '<script src="target.html"></script>',      "script src relative -> target")
    page("object-rel",  '<object data="target.html"></object>',     "object data relative -> target")
    page("embed-rel",   '<embed src="target.html">',                "embed src relative -> target")
    page("css-import-rel", '<style>@import "target.html";</style>', "CSS @import relative -> target")
    page("css-bg-rel",  '<div style="background:url(target.html)">x</div>', "CSS background url relative -> target")

    # ── Chains / nesting (relative each hop) ──
    page("chain-1", "hop 1", "relative redirect chain hop1 -> hop2 -> target", head=meta("chain-2.html"))
    page("chain-2", "hop 2", "chain hop2 -> target", head=meta("target.html"), entry=False)
    page("nested-outer", '<iframe src="nested-inner.html"></iframe>',
         "page whose iframe loads a page that links to the target")
    page("nested-inner", '<a href="target.html">link</a>', "inner page linking to target", entry=False)

    return cases


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--out", default="docs")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    out = os.path.join(HERE, args.out)

    build(base)
    write_file(os.path.join(out, ".nojekyll"), "")
    for c in cases:
        write_file(os.path.join(out, c["path"]), c["html"])
    idx = "\n".join('<li><code>%s</code> -> <a href="%s">%s</a></li>'
                    % (c["id"], os.path.basename(c["path"]), c["path"]) for c in cases)
    write_file(os.path.join(out, ROOT, "index.html"),
               PAGE_TMPL.format(title="resolve-to-one-target", head="", body="<ul>\n" + idx + "\n</ul>"))

    lines = ["# >>> RESOLVE BEGIN",
             "# Pages that RESOLVE to one target (%s/%s/target.html). Make the target phishing;" % (base, ROOT),
             "# each wrapper mail should then quarantine. Generated by resolve_cases.py.", ""]
    n = 0
    for c in cases:
        if not c.get("entry"):
            continue
        n += 1
        lines += ["id=%s" % c["id"], "url=%s/%s" % (base, c["path"]),
                  "desc=%s" % c["desc"], "verdict=%s" % c["verdict"], ""]
    lines.append("# <<< RESOLVE END")
    write_file(os.path.join(HERE, "resolve.properties"), "\n".join(lines) + "\n")

    print("TARGET (make phishing): %s/%s/target.html" % (base, ROOT))
    print("pages: %d | entry cases: %d -> resolve.properties" % (len(cases), n))


if __name__ == "__main__":
    main()
