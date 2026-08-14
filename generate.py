#!/usr/bin/env python3
"""
Generate the URL-scan browser-resolution test site (GitHub Pages) from cases.json.

Deterministic cases carry an absolute <base href>, so their resolved URLs are the same no
matter where you deploy. The meta-refresh case has no base and resolves against its serving
URL, so its expected URL includes the deploy origin ({BASE}) at test time.

Usage:
    python3 generate.py            # -> ./docs   (commit this folder; GH Pages "/docs" source)
    python3 generate.py --out site # write into ./site instead
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

PAGE_TMPL = ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
             "<title>{title}</title>\n</head>\n<body>\n{body}\n</body>\n</html>\n")


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print("  wrote", os.path.relpath(path, HERE))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs", help="output directory (default: docs)")
    args = ap.parse_args()

    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]

    out = os.path.join(HERE, args.out)

    # .nojekyll so GitHub Pages serves files verbatim (no Jekyll processing).
    write_file(os.path.join(out, ".nojekyll"), "")

    index_rows = []
    for c in cases:
        page = c.get("page")
        if page:
            write_file(os.path.join(out, page["path"]),
                       PAGE_TMPL.format(title=c["id"], body=page["html"]))
        index_rows.append("<li><code>{}</code> &rarr; <a href=\"{}\">{}</a></li>".format(
            c["id"], c["mailPath"], c["mailPath"]))

    index_body = ("<h1>URL-scan browser-resolution test site</h1>\n"
                  "<p>Each link is a page the antispam URL scanner fetches; it contains relative "
                  "references the backend should resolve like a browser. See cases.json for the "
                  "expected resolved URLs.</p>\n<ul>\n" + "\n".join(index_rows) + "\n</ul>\n")
    write_file(os.path.join(out, "index.html"),
               PAGE_TMPL.format(title="URL-scan test site", body=index_body))

    print("\nDone. Commit the '{}' folder and enable GitHub Pages on it. Then run the test with:".format(args.out))
    print("  -Durlscan.site=https://<user>.github.io/<repo>")


if __name__ == "__main__":
    sys.exit(main())
