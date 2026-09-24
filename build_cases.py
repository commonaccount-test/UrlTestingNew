#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builds cases.json for the webpage URL-extraction sanity.

Structure (mail links to a page; backend fetches it and extracts URLs from the page):
  1. single/     — ONE URL per page, one per type (https, http, query, fragment, port, ...)
  2. combined/   — one page mixing several edge-case types together
  3. bulk/       — many URLs of each type in one page
  4. base-relative/ — a <base href> + many relative anchors grouped in one page (per base theme)
  5. relative/   — relative refs resolved against the serving URL (no base)
  6. negative/   — strings that must NOT be extracted
  7. info/       — behaviours the spec leaves open (log only, no assertion)

Every page separates its URLs with <br><br> / <hr> for readability.

Outcome per case:
  present      : absolute URLs that MUST appear in the antispam-log urlList (deterministic)
  presentTmpl  : same, with {BASE} (full deploy base incl. /repo) / {ORIGIN} (scheme+host) placeholders
  absent       : must NOT appear
  info=True    : log only, no assertion
"""
import json, os, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
cases = []

def puny(host):
    """Punycode form of an IDN host (best effort); None if it can't be encoded."""
    try:
        return ".".join(
            lbl.encode("idna").decode("ascii") if any(ord(ch) > 127 for ch in lbl) else lbl
            for lbl in host.split("."))
    except Exception:
        return None

def pct(s):
    """Percent-encode a path/query component (keep it readable — no safe chars)."""
    return urllib.parse.quote(s, safe="")

# ── Cache-buster ────────────────────────────────────────────────────────────────────────────
# The URL scanner caches results by URL hash. To force a fresh fetch+extract, BUMP THIS on every
# new run (v1 -> v2 -> ...). It is prefixed to every page path, so all page URLs become new and
# the cache misses. Relative-resolution templates below include VER because the page dir carries it.
VER = "v1"

def add(path, html, present=None, presentTmpl=None, presentAny=None, absent=None, info=False, desc=""):
    # `path` is an extensionless id-path, e.g. "single/https".
    cid = path.replace("/", "_")       # single/https -> single_https (stable across versions)
    full = VER + "/" + path + ".html"  # v1/single/https.html (the actual page path & mail URL)
    cases.append({
        "id": cid, "desc": desc, "mailPath": full,
        "page": {"path": full, "html": html},
        "present": present or [], "presentTemplate": presentTmpl or [],
        "presentAny": presentAny or [],  # each group: at least ONE accepted form must be extracted
        "absent": absent or [], "info": bool(info),
    })

def A(url, text="link"):
    return '<a href="%s">%s</a>' % (url, text)

def rows(items):
    """Join snippets with clear vertical spacing."""
    return "\n<br><br>\n".join(items)

def section(title, items):
    return '<h3>%s</h3>\n%s' % (title, rows(items))

# ══════════════════════════════════════════════════════════════════════════════════════════
# 1. SINGLE — one URL per page, one per type
# ══════════════════════════════════════════════════════════════════════════════════════════

# -- Hyperlinked, absolute, deterministic (assert present) --
SINGLE_HREF = [
    ("single/https",            "https://example.com/page",                      "HTTPS in href"),
    ("single/http",             "http://example.com/page",                       "HTTP in href"),
    ("single/query-single",     "https://example.com/page?id=123",               "single query param"),
    ("single/fragment",         "https://example.com/page#section",              "fragment"),
    ("single/query-fragment",   "https://example.com/page?id=10#details",        "query + fragment"),
    ("single/port-http",        "http://example.com:8080/test",                  "http with port"),
    ("single/port-https",       "https://example.com:8443/login",                "https with port"),
    ("single/encoding-space",   "https://example.com/my%20page",                 "percent-encoded space"),
    ("single/encoding-slash",   "https://example.com/path%2Fwith%2Fslashes",     "encoded slashes"),
    ("single/encoding-unicode", "https://example.com/%E6%97%A5%E6%9C%AC%E8%AA%9E", "percent-encoded unicode"),
    ("single/special-hyphen",   "https://example.com/my-test-page",              "hyphen"),
    ("single/special-tilde",    "https://example.com/~user",                     "tilde"),
    ("single/path-deep",        "https://example.com/a/b/c/d/resource",          "deep path"),
    ("single/punycode",         "https://xn--mnich-kva.com",                     "punycode domain"),
    ("single/protocol-relative","//example.com/page",                            "protocol-relative -> https"),
]
for path, url, d in SINGLE_HREF:
    exp = "https://example.com/page" if url.startswith("//") else url
    add(path, A(url), present=[exp], desc=d)

# query with multiple params via &amp; entity (decodes to &)
add("single/query-multi", A("https://example.com/search?q=test&amp;sort=desc&amp;page=2"),
    present=["https://example.com/search?q=test&sort=desc&page=2"], desc="multiple query params (&amp;)")
add("single/entity-amp", A("https://example.com/search?a=1&amp;b=2"),
    present=["https://example.com/search?a=1&b=2"], desc="&amp; entity decoded")

# -- Plain-text, absolute, deterministic --
add("single/plaintext-https", "<p>Visit https://example.com/page for details.</p>",
    present=["https://example.com/page"], desc="https as plain text")
add("single/plaintext-http", "<p>Visit http://example.com/page here.</p>",
    present=["http://example.com/page"], desc="http as plain text")

# -- Punctuation: clean URL present, punctuation-appended variant absent --
add("single/punct-period", "<p>Visit https://example.com.</p>",
    present=["https://example.com"], absent=["https://example.com."], desc="trailing period stripped")
add("single/punct-comma", "<p>Visit https://example.com, and continue.</p>",
    present=["https://example.com"], absent=["https://example.com,"], desc="trailing comma stripped")
add("single/punct-parens", "<p>(https://example.com)</p>",
    present=["https://example.com"], absent=["https://example.com)"], desc="wrapped in parentheses")
add("single/punct-exclaim", "<p>Visit https://example.com!</p>",
    present=["https://example.com"], absent=["https://example.com!"], desc="trailing exclamation stripped")

# -- Visible text differs from href --
add("single/text-differs", A("https://example.com/actual-page", "Click Here"),
    present=["https://example.com/actual-page"], absent=["Click Here"], desc="visible text != href")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 5. RELATIVE (no base) — resolved against the serving URL. Pages live at pages/relative/<x>.html
#    so ../ -> {BASE}/pages, ./ -> {BASE}/pages/relative, / -> {ORIGIN}
# ══════════════════════════════════════════════════════════════════════════════════════════
# Pages live at {BASE}/<VER>/relative/<x>.html, so: / -> {ORIGIN} ; ../ -> {BASE}/<VER> ; ./ -> {BASE}/<VER>/relative
add("relative/root",     A("/login"),            presentTmpl=["{ORIGIN}/login"],                     desc="root-relative")
add("relative/parent",   A("../login"),          presentTmpl=["{BASE}/%s/login" % VER],              desc="parent-relative")
add("relative/current",  A("./login"),           presentTmpl=["{BASE}/%s/relative/login" % VER],     desc="current-dir relative")
add("relative/query",    A("/search?q=test"),    presentTmpl=["{ORIGIN}/search?q=test"],             desc="root-relative + query")
add("relative/fragment", A("/page#section1"),    presentTmpl=["{ORIGIN}/page#section1"],              desc="root-relative + fragment")
add("relative/meta-refresh", '<meta http-equiv="refresh" content="5;url=next">',
    presentTmpl=["{BASE}/%s/relative/next" % VER], desc="meta-refresh path-relative target")

# Exhaustive dot-segment resolution with NO base — resolved against the serving URL
# ({BASE}/<VER>/relative/deep-dot-segments.html). ../ -> {BASE}/<VER> ; ../../ -> {BASE} ; ../../../ -> {ORIGIN}.
_deep = [
    ("../a1",            "{BASE}/%s/a1" % VER),
    ("../../a2",         "{BASE}/a2"),
    ("../../../a3",      "{ORIGIN}/a3"),
    ("../../../../a4",   "{ORIGIN}/a4"),                       # over-pop clamps at origin root
    ("./a5",             "{BASE}/%s/relative/a5" % VER),
    ("b/../a6",          "{BASE}/%s/relative/a6" % VER),
    ("x/y/../../a7",     "{BASE}/%s/relative/a7" % VER),
    ("/a8",              "{ORIGIN}/a8"),                       # root-relative
    ("/./a9",            "{ORIGIN}/a9"),
    ("/../a10",          "{ORIGIN}/a10"),                      # clamp
    (".././a11",         "{BASE}/%s/a11" % VER),
]
add("relative/deep-dot-segments-2",
    section("no-base relative — resolved vs serving URL", [A(ref, ref) for ref, _ in _deep]),
    presentTmpl=[resolved for _, resolved in _deep],
    desc="every ./ and ../ combination with no base (serving-URL resolution)")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 7a. LOCATION — same valid URL in different HTML locations. Must be extracted (assert present).
# ══════════════════════════════════════════════════════════════════════════════════════════
add("location/img-src",         '<img src="https://example.com/image.png">',
    present=["https://example.com/image.png"], desc="URL in <img src>")
add("location/form-action",     '<form action="https://example.com/submit"></form>',
    present=["https://example.com/submit"], desc="URL in <form action>")
add("location/link-stylesheet", '<link href="https://example.com/style.css" rel="stylesheet">',
    present=["https://example.com/style.css"], desc="URL in <link href>")
add("location/js-string",       '<script>const u = "https://example.com/api/users";</script>',
    present=["https://example.com/api/users"], desc="URL in JS string")
add("location/js-redirect",     '<script>window.location = "https://example.com/login";</script>',
    present=["https://example.com/login"], desc="URL in JS redirect")
add("location/comment",         "<!-- https://example.com/comment -->",
    present=["https://example.com/comment"], desc="URL in HTML comment")
add("location/hidden",          '<div style="display:none">https://example.com/hidden</div>',
    present=["https://example.com/hidden"], desc="URL in display:none block")
add("location/duplicate",       rows([A("https://dup.example.com"), "<p>https://dup.example.com</p>"]),
    present=["https://dup.example.com"], desc="same URL as hyperlink + plain text (must appear at least once)")
add("single/underscore",        "<p>https://example.com/my_test_page</p>",
    present=["https://example.com/my_test_page"], desc="underscore in path")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 7b. REPRESENTATION — must be extracted; only the exact string form is uncertain (presentAny).
# ══════════════════════════════════════════════════════════════════════════════════════════
def any_group(*forms):
    return [f for f in forms if f]

# IDN — accept unicode OR punycode form
add("representation/idn-domain", A("https://münich.com"),
    presentAny=[any_group("https://münich.com", "https://" + (puny("münich.com") or ""))],
    desc="IDN domain (unicode or punycode)")
add("representation/idn-domain-path", A("https://münich.com/café"),
    presentAny=[any_group(
        "https://münich.com/café", "https://münich.com/" + pct("café"),
        "https://%s/café" % puny("münich.com"), "https://%s/%s" % (puny("münich.com"), pct("café")))],
    desc="IDN domain + unicode path")
add("representation/idn-nonlatin", A("https://例え.テスト"),
    presentAny=[any_group("https://例え.テスト", "https://" + (puny("例え.テスト") or ""))],
    desc="non-Latin IDN")
add("representation/idn-mixed", A("https://例え.xn--p1ai"),
    presentAny=[any_group("https://例え.xn--p1ai", "https://" + (puny("例え.xn--p1ai") or ""))],
    desc="unicode + punycode label")
add("representation/idn-cyrillic", A("https://пример.рф"),
    presentAny=[any_group("https://пример.рф", "https://" + (puny("пример.рф") or ""))],
    desc="Cyrillic IDN domain (unicode or punycode)")
# Unicode in path / query — accept raw OR percent-encoded
add("representation/unicode-path", "<p>https://example.com/日本語</p>",
    presentAny=[any_group("https://example.com/日本語", "https://example.com/" + pct("日本語"))],
    desc="unicode path")
add("representation/unicode-query", "<p>https://example.com/search?q=தமிழ்</p>",
    presentAny=[any_group("https://example.com/search?q=தமிழ்", "https://example.com/search?q=" + pct("தமிழ்"))],
    desc="unicode query")
# No protocol — accept as-is OR with http:// prepended
add("representation/no-protocol-domain", "<p>Visit example.com here.</p>",
    presentAny=[any_group("http://example.com", "example.com")], desc="bare domain (http:// may be prepended)")
add("representation/no-protocol-www", "<p>Visit www.example.com here.</p>",
    presentAny=[any_group("http://www.example.com", "www.example.com")], desc="www domain, no protocol")
add("representation/no-protocol-path", "<p>Visit example.com/products/item1 here.</p>",
    presentAny=[any_group("http://example.com/products/item1", "example.com/products/item1")],
    desc="bare domain + path")
# Case — accept normalized or as-is
add("representation/uppercase-protocol", "<p>HTTP://EXAMPLE.COM</p>",
    presentAny=[any_group("http://example.com", "http://EXAMPLE.COM", "HTTP://EXAMPLE.COM")],
    desc="uppercase protocol/host")
add("representation/mixed-case-host", "<p>https://Example.COM/Test</p>",
    presentAny=[any_group("https://example.com/Test", "https://Example.COM/Test", "https://example.com/test")],
    desc="mixed-case host")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 7c. INFO — genuinely malformed / validity-open (log only; asserting either way would guess).
# ══════════════════════════════════════════════════════════════════════════════════════════
add("info/invalid-host",      "<p>https://example..com</p>",  info=True, desc="double-dot host")
add("info/incomplete-domain", "<p>https://example</p>",       info=True, desc="single-label host")
add("info/invalid-scheme",    "<p>https:///example.com</p>",  info=True, desc="triple slash after scheme")
add("info/space-in-url",      "<p>https:// example.com</p>",   info=True, desc="space inside URL")
add("info/domain-text",       "<p>hello.world</p>",            info=True, desc="ordinary dotted text")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 6. NEGATIVE — must NOT be extracted
# ══════════════════════════════════════════════════════════════════════════════════════════
add("negative/empty-protocol", "<p>https://</p>",   absent=["https://"],      desc="empty protocol")
add("negative/leading-dot",    "<p>.example.com</p>", absent=[".example.com"], desc="leading dot")
add("negative/incomplete-www", "<p>www.</p>",       absent=["www."],          desc="incomplete www")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 2. COMBINED — one page mixing several edge-case types (well spaced)
# ══════════════════════════════════════════════════════════════════════════════════════════
combined_present = [
    "https://example.com/page?id=123",
    "https://example.com/page#section",
    "https://example.com/page?id=10#details",
    "https://example.com:8443/login",
    "https://example.com/my%20page",
    "https://example.com/a/b/c/d/resource",
    "https://xn--mnich-kva.com",
]
combined_html = section("Edge-case URL types (one of each)", [
    A("https://example.com/page?id=123", "query"),
    A("https://example.com/page#section", "fragment"),
    A("https://example.com/page?id=10#details", "query+fragment"),
    A("https://example.com:8443/login", "port"),
    A("https://example.com/my%20page", "encoded-space"),
    A("https://example.com/a/b/c/d/resource", "deep-path"),
    A("https://xn--mnich-kva.com", "punycode"),
])
add("combined/edge-cases", combined_html, present=combined_present, desc="one URL of each edge type")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 3. BULK — many URLs of each type in one page
# ══════════════════════════════════════════════════════════════════════════════════════════
def bulk(path, title, urls, desc):
    add(path, section(title, [A(u) for u in urls]), present=list(urls), desc=desc)

bulk("bulk/query", "Many query URLs", [
    "https://example.com/q1?a=1", "https://example.com/q2?b=2", "https://example.com/q3?c=3",
    "https://example.com/q4?d=4", "https://example.com/q5?e=5"], "5 query URLs")
bulk("bulk/fragment", "Many fragment URLs", [
    "https://example.com/f1#a", "https://example.com/f2#b", "https://example.com/f3#c",
    "https://example.com/f4#d", "https://example.com/f5#e"], "5 fragment URLs")
bulk("bulk/port", "Many port URLs", [
    "https://example.com:8443/p1", "http://example.com:8080/p2",
    "https://example.com:9443/p3", "http://example.com:3000/p4"], "4 port URLs")
bulk("bulk/path", "Many deep-path URLs", [
    "https://example.com/a/one", "https://example.com/a/b/two", "https://example.com/a/b/c/three",
    "https://example.com/a/b/c/d/four", "https://example.com/a/b/c/d/e/five"], "5 deep-path URLs")
bulk("bulk/punycode", "Many punycode URLs", [
    "https://xn--mnich-kva.com/1", "https://xn--nxasmq6b.com/2", "https://xn--fiqs8s.com/3"], "3 punycode URLs")
# Bulk of all types together
bulk("bulk/all-types", "Many URLs, all types together", [
    "https://example.com/plain", "http://example.com/plain2",
    "https://example.com/q?a=1&amp;b=2".replace("&amp;", "&"),  # keep raw & in expected
    "https://example.com/frag#top", "https://example.com:8443/port",
    "https://example.com/enc%20oded", "https://example.com/a/b/c/deep",
    "https://xn--mnich-kva.com/puny", "https://example.com/~tilde",
    "https://example.com/my-hyphen-page"], "10 URLs spanning all types")
# fix: the all-types page HTML should send the &amp; form but expect the & form
cases[-1]["page"]["html"] = section("Many URLs, all types together", [
    A("https://example.com/plain"), A("http://example.com/plain2"),
    A("https://example.com/q?a=1&amp;b=2"), A("https://example.com/frag#top"),
    A("https://example.com:8443/port"), A("https://example.com/enc%20oded"),
    A("https://example.com/a/b/c/deep"), A("https://xn--mnich-kva.com/puny"),
    A("https://example.com/~tilde"), A("https://example.com/my-hyphen-page")])

# ══════════════════════════════════════════════════════════════════════════════════════════
# 4. BASE + RELATIVE — one <base href> + many relative anchors grouped per page (per base theme)
#    (base href is absolute, so page path is irrelevant to resolution)
# ══════════════════════════════════════════════════════════════════════════════════════════
def base_page(path, base, pairs, desc, extra_info_refs=None):
    """pairs: list of (relativeRef, resolvedAbsolute). extra_info_refs: refs with undefined outcome."""
    anchors = ['<base href="%s" target="_blank">' % base]
    present = []
    for ref, resolved in pairs:
        anchors.append(A(ref, ref))
        present.append(resolved)
    for ref in (extra_info_refs or []):
        anchors.append(A(ref, ref))
    html = section("base = " + base, anchors)
    add(path, html, present=present, desc=desc)

base_page("base-relative/directory", "https://example.com/a/b/", [
    ("c/d",                    "https://example.com/a/b/c/d"),
    ("x/y/z",                  "https://example.com/a/b/x/y/z"),
    ("../up",                  "https://example.com/a/up"),
    ("./same",                 "https://example.com/a/b/same"),
    ("?q=1",                   "https://example.com/a/b/?q=1"),
    ("#frag",                  "https://example.com/a/b/#frag"),
    ("/root",                  "https://example.com/root"),
    ("//cdn.example.com/p",    "https://cdn.example.com/p"),
    ("https://other.com/abs",  "https://other.com/abs"),
], "directory base + every relative shape")

base_page("base-relative/no-trailing-slash", "https://drive.google.com/a/b/c/d/ergvetr", [
    ("file/g",     "https://drive.google.com/a/b/c/d/file/g"),
    ("../x",       "https://drive.google.com/a/b/c/x"),
    ("../../y",    "https://drive.google.com/a/b/y"),
    ("/root",      "https://drive.google.com/root"),
], "no-trailing-slash base (last segment trimmed) + traversal")

base_page("base-relative/backslash", "https://drive.google.com/ergvetr\\", [
    ("file",   "https://drive.google.com/ergvetr/file"),
    ("/file",  "https://drive.google.com/file"),
], "backslash-terminated base normalized to /",
   extra_info_refs=["file\\d\\asj", "..\\c\\view"])

base_page("base-relative/idn", "https://xn--mnchen-3ya.de/reports/", [
    ("summary/q1?lang=de", "https://xn--mnchen-3ya.de/reports/summary/q1?lang=de"),
    ("../data",            "https://xn--mnchen-3ya.de/data"),
], "punycode base + relative")

base_page("base-relative/ip-port", "https://[2001:db8::1]:8080/api/", [
    ("v2/status", "https://[2001:db8::1]:8080/api/v2/status"),
    ("../x",      "https://[2001:db8::1]:8080/x"),
], "IPv6 + port base + relative")

base_page("base-relative/auth", "https://user:pass@example.com/secure/", [
    ("dashboard?tab=1", "https://user:pass@example.com/secure/dashboard?tab=1"),
    ("../public",       "https://user:pass@example.com/public"),
], "userinfo (user:pass@) base + relative")

base_page("base-relative/encoding", "https://example.com/caf%C3%A9/", [
    ("menu%20item",           "https://example.com/caf%C3%A9/menu%20item"),
    ("path%2Fwith%2Fslashes", "https://example.com/caf%C3%A9/path%2Fwith%2Fslashes"),
], "percent-encoded base + relative")

base_page("base-relative/absolute-override", "https://example.com/dir/", [
    ("ftp://external.com/file.txt", "ftp://external.com/file.txt"),
    ("//cdn.example.com/x",         "https://cdn.example.com/x"),
], "anchors overriding the base (own scheme / protocol-relative)")

# Exhaustive dot-segment resolution against a DEEP absolute base (a/b/c/d/e/) — every ./ ../ combo.
base_page("base-relative/deep-dot-segments-2", "https://example.com/a/b/c/d/e/", [
    ("f1",                       "https://example.com/a/b/c/d/e/f1"),
    ("./f2",                     "https://example.com/a/b/c/d/e/f2"),
    ("../f3",                    "https://example.com/a/b/c/d/f3"),
    ("../../f4",                 "https://example.com/a/b/c/f4"),
    ("../../../f5",              "https://example.com/a/b/f5"),
    ("../../../../f6",           "https://example.com/a/f6"),
    ("../../../../../f7",        "https://example.com/f7"),
    ("../../../../../../f8",     "https://example.com/f8"),        # over-pop clamps at root
    (".././f9",                  "https://example.com/a/b/c/d/f9"),
    ("x/../f10",                 "https://example.com/a/b/c/d/e/f10"),
    ("x/y/../../f11",            "https://example.com/a/b/c/d/e/f11"),
    ("/g1",                      "https://example.com/g1"),        # root-relative discards base path
    ("/./g2",                    "https://example.com/g2"),
    ("/../g3",                   "https://example.com/g3"),        # clamp at root
    ("/a/../g4",                 "https://example.com/g4"),
], "every ./ and ../ combination against a deep base")

# Subdomain base + relatives (host with multiple labels is preserved; protocol-relative to another sub).
base_page("base-relative/subdomain-2", "https://a1.b2.c3.example.com/p/q/", [
    ("r1",                          "https://a1.b2.c3.example.com/p/q/r1"),
    ("../r2",                       "https://a1.b2.c3.example.com/p/r2"),
    ("../../r3",                    "https://a1.b2.c3.example.com/r3"),
    ("/r4",                         "https://a1.b2.c3.example.com/r4"),
    ("//cdn.assets.example.com/r5", "https://cdn.assets.example.com/r5"),
], "multi-label subdomain base + relative / protocol-relative to another subdomain")

# multiple <base> tags: first valid wins
add("base-relative/multiple-base",
    section("two base tags — first should win", [
        '<base href="https://first-base.com/dir/" target="_blank">',
        '<base href="https://second-base.com/other/" target="_blank">',
        A("page", "page")]),
    present=["https://first-base.com/dir/page"], desc="multiple <base> tags, first wins")

# base + relative undefined-outcome variants (info)
add("base-relative/undefined",
    section("base-relative edge cases (undefined outcome)", [
        '<base href="https://drive.google.com\\ergvetr" target="_blank">',
        A("file/d/asj", "backslash-host base"),
        '<base href="drive.google.com/folder/" target="_blank">',
        A("file/d/asj", "scheme-less base")]),
    info=True, desc="scheme-less / backslash-host bases (undefined)")

# ══════════════════════════════════════════════════════════════════════════════════════════
# 8. MISSED — additional URL locations/representations (missed_webpage_url_extraction_test_cases)
#    All real http(s) URLs are asserted present; non-http schemes / dynamic-exec / encoded-ambiguous
#    are info; response-header & HTTP-redirect cases are omitted (not coverable on GitHub Pages).
# ══════════════════════════════════════════════════════════════════════════════════════════

# -- 1. Meta refresh variants --
add("missed/meta-immediate-absolute", '<meta http-equiv="refresh" content="0;url=https://example.com/immediate">',
    present=["https://example.com/immediate"], desc="meta refresh, immediate absolute")
add("missed/meta-delay-spaces", '<meta http-equiv="refresh" content="5; url=https://example.com/path">',
    present=["https://example.com/path"], desc="meta refresh, delay + space before url")
add("missed/meta-relative", '<meta http-equiv="refresh" content="5;url=/login">',
    presentTmpl=["{ORIGIN}/login"], desc="meta refresh, root-relative target")
add("missed/meta-quoted-idn", '<meta http-equiv="refresh" content="5;url=\'https://münich.com\'">',
    presentAny=[any_group("https://münich.com", "https://" + (puny("münich.com") or ""))],
    desc="meta refresh, quoted IDN target")

# -- 2. Link and metadata URLs --
add("missed/link-canonical", '<link rel="canonical" href="https://example.com/canonical">',
    present=["https://example.com/canonical"], desc="rel=canonical")
add("missed/link-alternate", '<link rel="alternate" hreflang="fr" href="https://example.com/fr">',
    present=["https://example.com/fr"], desc="rel=alternate hreflang")
add("missed/link-amp", '<link rel="amphtml" href="https://example.com/amp">',
    present=["https://example.com/amp"], desc="rel=amphtml")
add("missed/link-prev", '<link rel="prev" href="https://example.com/p/1">',
    present=["https://example.com/p/1"], desc="rel=prev")
add("missed/og-url", '<meta property="og:url" content="https://example.com/og-page">',
    present=["https://example.com/og-page"], desc="Open Graph og:url")
add("missed/og-image", '<meta property="og:image" content="https://example.com/og-image.jpg">',
    present=["https://example.com/og-image.jpg"], desc="Open Graph og:image")
add("missed/twitter-url", '<meta name="twitter:url" content="https://example.com/tw-page">',
    present=["https://example.com/tw-page"], desc="twitter:url")
add("missed/meta-base-only", '<base href="https://example.com/base-only/">',
    info=True, desc="bare <base href> (is the base URL itself extracted?)")

# -- 3. Embedded, media and form URLs --
add("missed/iframe", '<iframe src="https://example.com/frame"></iframe>',
    present=["https://example.com/frame"], desc="iframe src")
add("missed/object", '<object data="https://example.com/file.pdf"></object>',
    present=["https://example.com/file.pdf"], desc="object data")
add("single/eicar-pdf",
    A("https://github.com/fire1ce/eicar-standard-antivirus-test-files/raw/refs/heads/master/eicar-adobe-acrobat-attachment.pdf",
      "EICAR test PDF"),
    present=["https://github.com/fire1ce/eicar-standard-antivirus-test-files/raw/refs/heads/master/eicar-adobe-acrobat-attachment.pdf"],
    desc="EICAR Adobe Acrobat test PDF hyperlink")
add("single/eicar-pdf-2",
    A("https://github.com/fire1ce/eicar-standard-antivirus-test-files/raw/refs/heads/master/eicar-adobe-acrobat-attachment.pdf",
      "EICAR test PDF (link 2)"),
    present=["https://github.com/fire1ce/eicar-standard-antivirus-test-files/raw/refs/heads/master/eicar-adobe-acrobat-attachment.pdf"],
    desc="EICAR Adobe Acrobat test PDF hyperlink (second page)")
add("missed/embed", '<embed src="https://example.com/embed-file">',
    present=["https://example.com/embed-file"], desc="embed src")
add("missed/img", '<img src="https://example.com/image.jpg">',
    present=["https://example.com/image.jpg"], desc="img src")
add("missed/srcset", '<img srcset="https://example.com/a.jpg 1x, https://example.com/b.jpg 2x">',
    present=["https://example.com/a.jpg", "https://example.com/b.jpg"], desc="srcset — each URL")
add("missed/video", '<video src="https://example.com/video.mp4"></video>',
    present=["https://example.com/video.mp4"], desc="video src")
add("missed/form-action", '<form action="https://example.com/form-submit"></form>',
    present=["https://example.com/form-submit"], desc="form action")
add("missed/formaction", '<button formaction="https://example.com/btn-submit">Go</button>',
    present=["https://example.com/btn-submit"], desc="button formaction")

# -- 4. JavaScript and event URLs --
add("missed/js-location-href", '<script>window.location.href = "https://example.com/js-href";</script>',
    present=["https://example.com/js-href"], desc="location.href")
add("missed/js-location-assign", '<script>location.assign("https://example.com/js-assign");</script>',
    present=["https://example.com/js-assign"], desc="location.assign")
add("missed/js-location-replace", '<script>location.replace("https://example.com/js-replace");</script>',
    present=["https://example.com/js-replace"], desc="location.replace")
add("missed/js-window-open", '<script>window.open("https://example.com/js-popup");</script>',
    present=["https://example.com/js-popup"], desc="window.open")
add("missed/js-array", '<script>const urls = ["https://example.com/one", "https://example.com/two"];</script>',
    present=["https://example.com/one", "https://example.com/two"], desc="static JS array")
add("missed/js-inline-onclick", '<a onclick="location.href=\'https://example.com/js-onclick\'">x</a>',
    present=["https://example.com/js-onclick"], desc="inline onclick handler")
add("missed/js-escaped", '<script>const url = "https:\\/\\/example.com\\/js-escaped";</script>',
    present=["https://example.com/js-escaped"], desc="escaped JS URL (backslash-slash)")

# -- 5. CSS and structured data --
add("missed/css-url", '<div style=\'background-image: url("https://example.com/banner.jpg")\'></div>',
    present=["https://example.com/banner.jpg"], desc="CSS url()")
add("missed/css-import", '<style>@import url("https://example.com/style.css");</style>',
    present=["https://example.com/style.css"], desc="CSS @import")
add("missed/css-font", '<style>@font-face { src: url("https://example.com/font.woff2"); }</style>',
    present=["https://example.com/font.woff2"], desc="@font-face src")
add("missed/json-ld",
    '<script type="application/ld+json">{"url":"https://example.com/ld-page","sameAs":["https://example.org/ld-a"]}</script>',
    present=["https://example.com/ld-page", "https://example.org/ld-a"], desc="JSON-LD structured data")
add("missed/data-attr", '<div data-url="https://example.com/data-page" data-href="https://example.org/data-page"></div>',
    present=["https://example.com/data-page", "https://example.org/data-page"], desc="data-* custom attributes")

# -- 6. SVG and less-common attributes --
add("missed/svg-href", '<svg><a href="https://example.com/svg-a">Link</a></svg>',
    present=["https://example.com/svg-a"], desc="SVG <a href>")
add("missed/svg-xlink", '<svg><use xlink:href="https://example.com/icon.svg#icon"></use></svg>',
    presentAny=[any_group("https://example.com/icon.svg#icon", "https://example.com/icon.svg")],
    desc="SVG xlink:href")
add("missed/area-href", '<map><area href="https://example.com/region"></map>',
    present=["https://example.com/region"], desc="image-map area href")
add("missed/script-src", '<script src="https://example.com/app.js"></script>',
    present=["https://example.com/app.js"], desc="script src")
add("missed/input-image-src", '<input type="image" src="https://example.com/button.png">',
    present=["https://example.com/button.png"], desc="input type=image src")
add("missed/lazy-data-src", '<img data-src="https://example.com/lazy.jpg">',
    present=["https://example.com/lazy.jpg"], desc="lazy-loaded data-src")

# -- 8. Encoding, special schemes and boundary cases --
add("missed/entity-amp", '<a href="https://example.com/search?a=1&amp;b=2">x</a>',
    present=["https://example.com/search?a=1&b=2"], desc="HTML entity &amp; decoded")
add("missed/unicode-escaped-js", '<script>var u = "\\u0068\\u0074\\u0074\\u0070\\u0073://example.com/uni";</script>',
    info=True, desc="unicode-escaped JS URL (needs \\u decode)")
add("missed/percent-encoded-string", "<p>https%3A%2F%2Fexample.com%2Fpct-login</p>",
    info=True, desc="percent-encoded URL string")
add("missed/fragment-only", '<a href="#section">x</a>', info=True, desc="fragment-only reference")
add("missed/scheme-mailto", '<a href="mailto:user@example.com">x</a>', info=True, desc="mailto scheme")
add("missed/scheme-tel", '<a href="tel:+911234567890">x</a>', info=True, desc="tel scheme")
add("missed/scheme-javascript", '<a href="javascript:alert(1)">x</a>', info=True, desc="javascript scheme")
add("missed/scheme-data", '<img src="data:image/png;base64,iVBORw0KGgo=">', info=True, desc="data URL")
add("missed/scheme-blob", '<a href="blob:https://example.com/uuid">x</a>', info=True, desc="blob URL")

# -- 9. DOM and nested-content boundaries --
add("missed/js-generated-dom", '<script>document.body.innerHTML = \'<a href="https://example.com/dynamic">\';</script>',
    info=True, desc="JS-generated DOM (needs execution)")
add("missed/template", '<template><a href="https://example.com/template">x</a></template>',
    present=["https://example.com/template"], desc="template content")
add("missed/noscript", '<noscript><a href="https://example.com/noscript">x</a></noscript>',
    present=["https://example.com/noscript"], desc="noscript content")
add("missed/hidden-attr", '<a hidden href="https://example.com/hidden-attr">x</a>',
    present=["https://example.com/hidden-attr"], desc="hidden attribute")
add("missed/css-hidden", '<div style="display:none"><a href="https://example.com/css-hidden">x</a></div>',
    present=["https://example.com/css-hidden"], desc="CSS display:none content")
# NOTE: §7 (HTTP redirects, relative Location, Link header, Content-Location, Refresh response header)
# and Shadow-DOM / recursive-iframe are NOT represented here — they need response headers / real 30x /
# JS execution / second-level fetch, which GitHub Pages + first-level scope can't exercise.

out = {
    "_readme": "Webpage URL-extraction sanity cases (GitHub Pages). Built by build_cases.py. "
               "Organised as single/ (one URL per type), combined/ (edge types mixed), bulk/ "
               "(many URLs per type), base-relative/ (a <base href> + many relative anchors per page), "
               "relative/ (resolved vs serving URL), negative/ (must-not-extract), info/ (open behaviour). "
               "present = absolute URLs that must appear in the antispam-log urlList; presentTemplate uses "
               "{BASE} (deploy base incl. /repo) / {ORIGIN} (scheme+host); absent = must not appear; "
               "info=true -> log only.",
    "cases": cases,
}
with open(os.path.join(HERE, "cases.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)

ap = sum(1 for c in cases if c["present"] or c["presentTemplate"])
an = sum(1 for c in cases if c["presentAny"])
aa = sum(1 for c in cases if c["absent"])
inf = sum(1 for c in cases if c["info"])
print("wrote cases.json: %d cases (present:%d present-any-form:%d absent:%d info:%d)" % (len(cases), ap, an, aa, inf))
