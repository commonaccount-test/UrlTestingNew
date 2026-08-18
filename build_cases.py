#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builds cases.json for the webpage URL-extraction sanity from a compact spec that mirrors
Downloads/webpage_url_extraction_test_cases(1).md (TC-URL-001..074) PLUS the base-href
resolution cases we already had.

Each case -> a webpage the mail links to. Outcome per case:
  present       : absolute URLs that MUST appear in the antispam-log urlList (deterministic)
  presentTmpl   : same, but with {BASE}/{ORIGIN} placeholders resolved at test time
                  {BASE}   = full deploy base (origin + repo subpath), e.g. https://u.github.io/repo
                  {ORIGIN} = scheme+host only,               e.g. https://u.github.io
  absent        : URLs/strings that must NOT appear (negatives / false-positives)
  info          : True  -> log only, no assertion (the MD's "verify whether..." open behaviours)

generate.py turns page.html into a static page; the Java test reads present/absent/info.
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
cases = []

def C(cid, html, present=None, presentTmpl=None, absent=None, info=False, desc=""):
    path = "pages/" + cid + ".html"
    cases.append({
        "id": cid,
        "desc": desc,
        "mailPath": path,
        "page": {"path": path, "html": html},
        "present": present or [],
        "presentTemplate": presentTmpl or [],
        "absent": absent or [],
        "info": bool(info),
    })

# ── Existing base-href resolution cases (deterministic; absolute <base href>) ───────────────
def CB(cid, html, present=None, presentTmpl=None, desc=""):
    """Base-href resolution case at its own path."""
    C(cid, html, present=present, presentTmpl=presentTmpl, desc=desc)

CB("all_formats",
   '<base href="https://example.com/a/b/">'
   '<a href="https://other.com/abs">absolute</a><a href="//cdn.example.com/p.png">prel</a>'
   '<a href="/login">root</a><a href="c/d">path</a><a href="../up">dotdot</a>'
   '<a href="?q=1">query</a><a href="#frag">frag</a>',
   present=["https://other.com/abs", "https://cdn.example.com/p.png", "https://example.com/login",
            "https://example.com/a/b/c/d", "https://example.com/a/up",
            "https://example.com/a/b/?q=1", "https://example.com/a/b/#frag"],
   desc="Every relative shape against one <base href>.")
CB("base_no_trailing",
   '<base href="https://drive.google.com/a/b/c/d/ergvetr"><a href="file/d/asj/view?usp=sharing">l</a>',
   present=["https://drive.google.com/a/b/c/d/file/d/asj/view?usp=sharing"],
   desc="Path-relative vs no-trailing-slash base (last segment trimmed).")
CB("root_relative_base",
   '<base href="https://drive.google.com/a/b/c/d/ergvetr"><a href="/file/d/asj/view?usp=sharing">l</a>',
   present=["https://drive.google.com/file/d/asj/view?usp=sharing"],
   desc="Root-relative discards entire base path.")
CB("base_directory",
   '<base href="https://drive.google.com/a/b/c/d/"><a href="file/d/asj/view?usp=sharing">l</a>',
   present=["https://drive.google.com/a/b/c/d/file/d/asj/view?usp=sharing"],
   desc="Directory base: nothing trimmed.")
CB("dotdot",
   '<base href="https://drive.google.com/a/b/c/d/ergvetr"><a href="../x">1</a><a href="../../y">2</a>',
   present=["https://drive.google.com/a/b/c/x", "https://drive.google.com/a/b/y"],
   desc="../ traversal.")
CB("proto_relative_anchor",
   '<base href="https://drive.google.com/ergvetr"><a href="//example.com/page?x=1">l</a>',
   present=["https://example.com/page?x=1"], desc="Protocol-relative anchor inherits base scheme.")
CB("absolute_override",
   '<base href="https://example.com/dir/"><a href="ftp://external.com/file.txt">l</a>',
   present=["ftp://external.com/file.txt"], desc="Anchor with own scheme overrides base.")
CB("backslash_base",
   '<base href="https://drive.google.com/ergvetr\\"><a href="file/d/asj/view?usp=sharing">l</a>',
   present=["https://drive.google.com/ergvetr/file/d/asj/view?usp=sharing"],
   desc="Backslash-terminated base normalized to /.")
CB("multiple_base",
   '<base href="https://first-base.com/dir/"><base href="https://second-base.com/other/"><a href="page">l</a>',
   present=["https://first-base.com/dir/page"], desc="First <base> wins.")
CB("idn_base",
   '<base href="https://xn--mnchen-3ya.de/reports"><a href="summary/q1?lang=de">l</a>',
   present=["https://xn--mnchen-3ya.de/summary/q1?lang=de"], desc="IDN/punycode base.")
CB("ip_port_base",
   '<base href="https://192.168.1.1:8443/admin"><a href="users/list?active=true">l</a>',
   present=["https://192.168.1.1:8443/users/list?active=true"], desc="IP+port base preserved.")
CB("query_fragment_base",
   '<base href="https://example.com/app?theme=dark#top"><a href="settings?tab=profile">l</a>',
   present=["https://example.com/settings?tab=profile"], desc="Base query dropped for new path.")
CB("encoding_base",
   '<base href="https://example.com/caf%C3%A9/"><a href="menu%20item">l</a>',
   present=["https://example.com/caf%C3%A9/menu%20item"], desc="Percent-encoding preserved.")
CB("non_anchor_base",
   '<base href="https://example.com/base/"><img src="logo.png"><form action="login"></form>'
   '<iframe src="embed/frame"></iframe>',
   present=["https://example.com/base/logo.png", "https://example.com/base/login",
            "https://example.com/base/embed/frame"], desc="img/form/iframe resolved like <a>.")
CB("meta_refresh_relative",
   '<meta http-equiv="refresh" content="5;url=next">',
   presentTmpl=["{BASE}/pages/next"], desc="Meta-refresh path-relative vs serving URL.")

# ── Base-href resolution STRESS matrix (restored from URLRewritingSanity DEV_STRESS_SAMPLES) ─
# Undefined/ambiguous outcomes (malformed markup, scheme-less refs, @-in-relative, backslash
# host, late <base>, broken attrs) are info-only; the rest assert the browser-resolved absolute.
def DS(cid, base, ref, present=None, info=False, desc=""):
    if base is None:
        html = '<a href="%s">link1</a>' % ref
    else:
        html = '<base href="%s" target="_blank"><br><br><a href="%s">link1</a>' % (base, ref)
    C(cid, html, present=([present] if present else None), info=info, desc=desc)

# -- Base-Relative --
DS("ds_br_notrailing", "https://drive.google.com/ergvetr", "file/d/asj/view?usp=sharing",
   "https://drive.google.com/file/d/asj/view?usp=sharing", desc="single-seg no-trailing base + path-rel")
DS("ds_br_root", "https://drive.google.com/ergvetr", "/file/d/asj/view?usp=sharing",
   "https://drive.google.com/file/d/asj/view?usp=sharing", desc="single-seg base + root-rel")
DS("ds_br_folder_trailing", "https://drive.google.com/folder/", "file/d/asj/view?usp=sharing",
   "https://drive.google.com/folder/file/d/asj/view?usp=sharing", desc="trailing-slash base + path-rel")
DS("ds_br_ab_dotdot", "https://drive.google.com/a/b/", "../c/view?usp=sharing",
   "https://drive.google.com/a/c/view?usp=sharing", desc="a/b/ + ../c")
DS("ds_br_nobase", None, "file/d/asj/view?usp=sharing", info=True, desc="no base + path-rel (undefined)")
# -- Backslash base/anchor --
DS("ds_bs_root", "https://drive.google.com/ergvetr\\", "/file/d/asj/view?usp=sharing",
   "https://drive.google.com/file/d/asj/view?usp=sharing", desc="backslash base + root-rel")
DS("ds_bs_host_backslash", "https://drive.google.com\\ergvetr", "file/d/asj/view?usp=sharing",
   info=True, desc="backslash in place of first path slash (undefined)")
DS("ds_bs_midpath", "https://drive.google.com/a\\b/", "file/d/asj/view?usp=sharing",
   info=True, desc="backslash mid-path (undefined)")
DS("ds_bs_rel_backslash", "https://drive.google.com/ergvetr/", "file\\d\\asj\\view?usp=sharing",
   info=True, desc="relative anchor uses backslashes (undefined)")
DS("ds_bs_dotdot", "https://drive.google.com/folder/", "..\\c\\view?usp=sharing",
   info=True, desc="backslash + ../ (undefined)")
# -- Malformed / broken HTML --
DS("ds_mal_base_unquoted", 'https://drive.google.com/ergvetr target=', "file/d/asj/view?usp=sharing",
   info=True, desc="unterminated base href quote (undefined)")
C("ds_mal_broken_quote", '<a href="https://example.com/broken-quote?a=1>link</a>', info=True,
  desc="unterminated anchor href quote (undefined)")
C("ds_mal_amp_raw", '<a href="https://example.com/page?a=1&b=2">link</a>',
  present=["https://example.com/page?a=1&b=2"], desc="raw & in href")
C("ds_mal_single_quoted", "<a href='https://example.com/single-quoted-href'>link</a>",
  present=["https://example.com/single-quoted-href"], desc="single-quoted href")
C("ds_mal_attr_glue", '<a href="https://example.com/attr-glue"target="_blank">link</a>',
  present=["https://example.com/attr-glue"], desc="attr glued to href close-quote")
# -- No-protocol / scheme-less --
DS("ds_np_base_protorel", "//drive.google.com/ergvetr", "file/d/asj/view?usp=sharing",
   "https://drive.google.com/file/d/asj/view?usp=sharing", desc="protocol-relative base + path-rel")
DS("ds_np_anchor_protorel_nobase", None, "//example.com/page?x=1",
   "https://example.com/page?x=1", desc="no base + protocol-relative anchor")
DS("ds_np_base_plus_protorel", "https://drive.google.com/ergvetr", "//example.com/page?x=1",
   "https://example.com/page?x=1", desc="base + protocol-relative anchor overrides host")
DS("ds_np_base_schemeless", "drive.google.com/folder/", "file/d/asj/view?usp=sharing",
   info=True, desc="scheme-less base (undefined)")
DS("ds_np_anchor_schemeless_nobase", None, "drive.google.com/file/d/asj?usp=sharing",
   info=True, desc="no base + scheme-less anchor (undefined)")
# -- IDN base --
DS("ds_idn_notrailing", "https://xn--mnchen-3ya.de/reports", "summary/q1?lang=de",
   "https://xn--mnchen-3ya.de/summary/q1?lang=de", desc="punycode base no-trailing + path-rel")
DS("ds_idn_fsqu_dotdot", "https://xn--fsqu00a.xn--0zwm56d/reports/", "../data/x",
   "https://xn--fsqu00a.xn--0zwm56d/data/x", desc="punycode base + ../")
DS("ds_idn_unicode_base", "https://münchen.de/reports", "summary/q1", info=True,
   desc="unicode base (representation undefined)")
DS("ds_idn_mgbh", "https://xn--mgbh0fb.xn--kgbechtv/dir/", "page",
   "https://xn--mgbh0fb.xn--kgbechtv/dir/page", desc="punycode base + trailing slash")
# -- IP & port base --
DS("ds_ip_v4port", "https://192.168.1.1:8443/admin", "users/list?active=true",
   "https://192.168.1.1:8443/users/list?active=true", desc="IPv4:port base")
DS("ds_ip_v6port", "https://[2001:db8::1]:8080/api/", "v2/status",
   "https://[2001:db8::1]:8080/api/v2/status", desc="IPv6:port base")
DS("ds_ip_v6noport", "https://[2001:db8::1]/api/", "v2/status",
   "https://[2001:db8::1]/api/v2/status", desc="IPv6 base no port")
DS("ds_ip_65535", "https://example.com:65535/root/", "nested/page",
   "https://example.com:65535/root/nested/page", desc="max-port base")
# -- Auth / credentials base --
DS("ds_auth_userpass", "https://user:pass@example.com/secure/", "dashboard?tab=1",
   "https://user:pass@example.com/secure/dashboard?tab=1", desc="user:pass@ base")
DS("ds_auth_user", "https://svc@example.com/", "path/to/x",
   "https://svc@example.com/path/to/x", desc="user@ base")
DS("ds_auth_at_relative", "https://user:pass@example.com/secure/", "account@notrelative",
   info=True, desc="@ in relative segment (undefined)")
# -- Query / fragment carried by base --
DS("ds_qf_newanchor", "https://example.com/app/section#anchor", "#newanchor",
   "https://example.com/app/section#newanchor", desc="fragment-only vs base with fragment")
DS("ds_qf_page_space_encoded", "https://example.com/app/", "page#section%20with%20space",
   "https://example.com/app/page#section%20with%20space", desc="encoded space in fragment")
DS("ds_qf_space_raw", "https://example.com/app/section#anchor", "#new anchor",
   info=True, desc="raw space in fragment (undefined)")
# -- Encoding variants base --
DS("ds_enc_slashes", "https://example.com/base/", "path%2Fwith%2Fslashes",
   "https://example.com/base/path%2Fwith%2Fslashes", desc="encoded slashes preserved")
DS("ds_enc_cafe_rel", "https://example.com/base/", "caf%C3%A9",
   "https://example.com/base/caf%C3%A9", desc="encoded utf8 in ref")
# -- Absolute anchor overrides base --
DS("ds_abs_ftp", "https://example.com/dir/", "ftp://external.com/file.txt",
   "ftp://external.com/file.txt", desc="ftp anchor overrides base")
DS("ds_abs_mailto", "https://example.com/dir/", "mailto:user@example.com",
   info=True, desc="mailto anchor (extraction undefined)")
# -- Multiple / late <base> --
C("ds_mb_first_wins",
  '<base href="https://first-base.com/dir/" target="_blank">'
  '<base href="https://second-base.com/other/" target="_blank"><br><br><a href="page">link1</a>',
  present=["https://first-base.com/dir/page"], desc="first valid <base> wins")
C("ds_mb_late",
  '<br><br><a href="page">link1</a><base href="https://late-base.com/dir/" target="_blank">',
  info=True, desc="<base> after the anchor (undefined)")
# -- HTML tag coverage --
C("ds_tag_unquoted_href", '<a href=https://example.com/unquoted-href>link</a>',
  present=["https://example.com/unquoted-href"], desc="unquoted href")
# -- Broken HTML extra --
C("ds_broken_empty_href", '<a href="">empty href</a>', info=True, desc="empty href (undefined)")
C("ds_broken_no_value", '<a href>no value at all</a>', info=True, desc="valueless href (undefined)")
C("ds_broken_mismatched_quote", '<a href=\'https://example.com/mismatched-quote">mismatched</a>',
  info=True, desc="mismatched quotes (undefined)")

# ── MD Section 3 — Hyperlinked URL cases ────────────────────────────────────────────────────
C("tc001", '<a href="https://example.com/page">Example</a>', present=["https://example.com/page"], desc="HTTPS in href")
C("tc002", '<a href="http://example.com/page">Example</a>', present=["http://example.com/page"], desc="HTTP in href")
C("tc003", '<a href="https://example.com/actual-page">Click Here</a>',
  present=["https://example.com/actual-page"], absent=["Click Here"], desc="Visible text differs from href")
C("tc004", "<a href='https://example.com/page'>Example</a>", present=["https://example.com/page"], desc="Single quotes")
C("tc005", '<a href = "https://example.com/page">Example</a>', present=["https://example.com/page"], desc="Spaces around href")
C("tc006", '<a\n  class="link"\n  href="https://example.com/page"\n>\n Example\n</a>',
  present=["https://example.com/page"], desc="Multiline anchor")

# ── Section 4 — Plain text ───────────────────────────────────────────────────────────────────
C("tc007", '<p>Visit https://example.com/page for more information.</p>', present=["https://example.com/page"], desc="HTTPS plain text")
C("tc008", '<p>Visit http://example.com/page.</p>', present=["http://example.com/page"], desc="HTTP plain text (trailing period)")
C("tc009", '<p>Our website is https://example.com</p>', present=["https://example.com"], desc="URL without hyperlink")

# ── Section 5 — URLs without protocol (open behaviour -> info) ───────────────────────────────
C("tc010", '<p>Visit example.com</p>', info=True, desc="Domain without protocol")
C("tc011", '<p>Visit www.example.com</p>', info=True, desc="www without protocol")
C("tc012", '<p>Visit example.com/products/item1</p>', info=True, desc="Protocol-less with path")
C("tc013", '<p>Visit example.com/search?q=test&amp;sort=desc</p>', info=True, desc="Protocol-less with query")

# ── Section 6 — Relative URLs (assert resolution vs serving URL; {ORIGIN} for root-relative) ─
C("tc014", '<a href="/login">Login</a>', presentTmpl=["{ORIGIN}/login"], desc="Root-relative")
C("tc015", '<a href="../login">Login</a>', presentTmpl=["{BASE}/login"], desc="Parent-relative (page under /t/)")
C("tc016", '<a href="./login">Login</a>', presentTmpl=["{BASE}/pages/login"], desc="Current-dir relative")
C("tc017", '<a href="/search?q=test">Search</a>', presentTmpl=["{ORIGIN}/search?q=test"], desc="Relative with query")
C("tc018", '<a href="/page#section1">Section</a>', presentTmpl=["{ORIGIN}/page#section1"], desc="Relative with fragment")

# ── Section 7 — Protocol-relative ────────────────────────────────────────────────────────────
C("tc019", '<a href="//example.com/page">Example</a>', present=["https://example.com/page"], desc="Protocol-relative -> https")

# ── Section 8 — IDN (representation open -> info) ────────────────────────────────────────────
C("tc020", '<a href="https://münich.com">Munich</a>', info=True, desc="Unicode domain")
C("tc021", '<a href="https://münich.com/café">Cafe</a>', info=True, desc="Unicode domain+path")
C("tc022", '<a href="https://例え.テスト">Example</a>', info=True, desc="Non-Latin IDN")
C("tc023", '<p>Visit https://münich.com for information.</p>', info=True, desc="IDN plain text")
C("tc024", '<p>https://münich.com https://例え.テスト https://δοκιμή.example</p>', info=True, desc="Multiple IDN")

# ── Section 9 — Punycode (ASCII -> deterministic) ───────────────────────────────────────────
C("tc025", '<a href="https://xn--mnich-kva.com">Munich</a>', present=["https://xn--mnich-kva.com"], desc="Punycode domain")
C("tc026", '<p>Visit https://xn--mnich-kva.com</p>', present=["https://xn--mnich-kva.com"], desc="Punycode plain text")
C("tc027", '<p>https://xn--example-xya.xn--example-9za</p>', info=True, desc="Multiple xn-- labels")

# ── Section 10 — Mixed IDN/Punycode (open -> info) ──────────────────────────────────────────
C("tc028", '<a href="https://例え.xn--p1ai">Example</a>', info=True, desc="Unicode + punycode label")
C("tc029", '<a href="https://xn--mnich-kva.com/日本語">Example</a>', info=True, desc="Punycode host + unicode path")
C("tc030", '<p>https://xn--mnich-kva.com/search?q=தமிழ்</p>', info=True, desc="Punycode host + unicode query")

# ── Section 11 — Unicode in path/query (representation open -> info; %-encoded ASCII asserted) ─
C("tc031", '<p>https://example.com/日本語</p>', info=True, desc="Unicode path")
C("tc032", '<p>https://example.com/தமிழ்</p>', info=True, desc="Tamil path")
C("tc033", '<p>https://example.com/search?q=தமிழ்</p>', info=True, desc="Unicode query")
C("tc034", '<p>https://example.com/%E6%97%A5%E6%9C%AC%E8%AA%9E</p>',
  present=["https://example.com/%E6%97%A5%E6%9C%AC%E8%AA%9E"], desc="Percent-encoded unicode")

# ── Section 12 — Query parameters ───────────────────────────────────────────────────────────
C("tc035", '<p>https://example.com/page?id=123</p>', present=["https://example.com/page?id=123"], desc="Single query")
C("tc036", '<p>https://example.com/search?q=test&amp;sort=desc&amp;page=2</p>',
  present=["https://example.com/search?q=test&sort=desc&page=2"], desc="Multiple query params")
C("tc037", '<p>https://example.com/search?q=hello%20world</p>',
  present=["https://example.com/search?q=hello%20world"], desc="Encoded chars in query")

# ── Section 13 — Fragment ───────────────────────────────────────────────────────────────────
C("tc038", '<p>https://example.com/page#section</p>', present=["https://example.com/page#section"], desc="Fragment")
C("tc039", '<p>https://example.com/page?id=10#details</p>', present=["https://example.com/page?id=10#details"], desc="Query+fragment")

# ── Section 14 — Ports ──────────────────────────────────────────────────────────────────────
C("tc040", '<p>http://example.com:8080/test</p>', present=["http://example.com:8080/test"], desc="HTTP with port")
C("tc041", '<p>https://example.com:8443/login</p>', present=["https://example.com:8443/login"], desc="HTTPS with port")

# ── Section 15 — Special characters ─────────────────────────────────────────────────────────
C("tc042", '<p>https://example.com/my-test-page</p>', present=["https://example.com/my-test-page"], desc="Hyphen")
C("tc043", '<p>https://example.com/my_test_page</p>', info=True, desc="Underscore (behaviour open)")
C("tc044", '<p>https://example.com/~user</p>', present=["https://example.com/~user"], desc="Tilde")
C("tc045", '<p>https://example.com/my%20page</p>', present=["https://example.com/my%20page"], desc="Percent encoding")

# ── Section 16 — Punctuation (assert clean URL present; trailing punct must be stripped) ─────
C("tc046", '<p>Visit https://example.com.</p>', present=["https://example.com"], absent=["https://example.com."], desc="Trailing period")
C("tc047", '<p>Visit https://example.com, and continue.</p>', present=["https://example.com"], absent=["https://example.com,"], desc="Trailing comma")
C("tc048", '<p>(https://example.com)</p>', present=["https://example.com"], absent=["https://example.com)"], desc="In parentheses")
C("tc049", '<p>"https://example.com"</p>', present=["https://example.com"], desc="In quotes")
C("tc050", '<p>Visit https://example.com!</p>', present=["https://example.com"], absent=["https://example.com!"], desc="Trailing exclamation")

# ── Section 17 — HTML entities ──────────────────────────────────────────────────────────────
C("tc051", '<a href="https://example.com/search?a=1&amp;b=2">Search</a>',
  present=["https://example.com/search?a=1&b=2"], desc="&amp; entity decoded")
C("tc052", '<p>https://example.com/x?a=1&amp;b=&quot;q&quot;&amp;c=&apos;r&apos;</p>', info=True, desc="Encoded chars in URL")

# ── Section 18 — URLs in other attributes (open -> info) ────────────────────────────────────
C("tc053", '<img src="https://example.com/image.png">', info=True, desc="img src")
C("tc054", '<form action="https://example.com/submit"></form>', info=True, desc="form action")
C("tc055", '<link href="https://example.com/style.css" rel="stylesheet">', info=True, desc="link stylesheet")

# ── Section 19 — URLs in JavaScript (open -> info) ──────────────────────────────────────────
C("tc056", '<script>const url = "https://example.com/api/users";</script>', info=True, desc="URL in JS string")
C("tc057", '<script>window.location = "https://example.com/login";</script>', info=True, desc="JS redirect")

# ── Section 20 — Duplicates (dedup behaviour open -> info) ───────────────────────────────────
C("tc058", '<a href="https://dup1.example.com">Example</a><p>https://dup1.example.com</p>', info=True, desc="Same URL hyperlink+text")
C("tc059", '<a href="https://dup2.example.com">One</a><a href="https://dup2.example.com">Two</a><p>https://dup2.example.com</p>', info=True, desc="Same URL multiple times")

# ── Section 21 — Case variations (normalization open -> info) ────────────────────────────────
C("tc060", '<p>HTTP://EXAMPLE.COM</p>', info=True, desc="Uppercase protocol")
C("tc061", '<p>https://Example.COM/Test</p>', info=True, desc="Mixed-case host")

# ── Section 22 — Hidden/commented (open -> info) ────────────────────────────────────────────
C("tc062", '<!-- https://example.com/comment -->', info=True, desc="URL in HTML comment")
C("tc063", '<div style="display:none">https://example.com/hidden</div>', info=True, desc="URL in hidden HTML")

# ── Section 23 — Invalid / negative ─────────────────────────────────────────────────────────
C("tc064", '<p>https://</p>', absent=["https://"], desc="Empty protocol -> not extracted")
C("tc065", '<p>https:///example.com</p>', info=True, desc="Invalid protocol format")
C("tc066", '<p>https:// example.com</p>', info=True, desc="Space inside URL")
C("tc067", '<p>https://example..com</p>', info=True, desc="Invalid hostname")
C("tc068", '<p>https://example</p>', info=True, desc="Incomplete domain (single label)")

# ── Section 24 — Email negatives — SKIPPED for now (email-ID extraction not in play) ─────────
# TC-069 / TC-070 omitted per request; re-add if email-as-URL extraction becomes a requirement.

# ── Section 25 — Domain-like negatives ──────────────────────────────────────────────────────
C("tc071", '<p>.example.com</p>', absent=[".example.com"], desc="Leading dot -> not extracted")
C("tc072", '<p>www.</p>', absent=["www."], desc="Incomplete www")
C("tc073", '<p>hello.world</p>', info=True, desc="Ordinary dotted text")

# ── Section 26 — Mixed representations (info: dump what's extracted) ─────────────────────────
C("tc074",
  '<a href="https://example.com/hyperlink">Hyperlink</a><p>https://example.com/plain-text</p>'
  '<p>www.example.org</p><p>example.net/page</p><a href="/relative">Relative</a>'
  '<a href="//cdn.example.com/file">Protocol relative</a><a href="https://münich.com">IDN</a>'
  '<a href="https://xn--mnich-kva.com">Punycode</a>',
  present=["https://example.com/hyperlink", "https://example.com/plain-text",
           "https://xn--mnich-kva.com"],
  presentTmpl=["{ORIGIN}/relative"],
  desc="Mixed URL representations (assert the deterministic ones).")

# ── Section 27 — Comprehensive page (info-only: log the full extraction) ─────────────────────
C("tc_comprehensive",
  '<h1>URL Extraction Test Page</h1>'
  '<a href="https://example.com/https">HTTPS URL</a><a href="http://example.com/http">HTTP URL</a>'
  '<p>https://example.com/plain-text</p><p>www.example.com/page</p><p>example.org/test</p>'
  '<a href="/login">Relative URL</a><a href="../about">Parent relative URL</a>'
  '<a href="//cdn.example.com/file.js">Protocol relative</a>'
  '<a href="https://münich.com">IDN URL</a><a href="https://例え.テスト">Unicode IDN</a>'
  '<a href="https://xn--mnich-kva.com">Punycode URL</a>'
  '<p>https://example.com/日本語</p><p>https://example.com/தமிழ்</p>'
  '<p>https://example.com/search?q=test&amp;page=2</p><p>https://example.com/page#section1</p>'
  '<p>https://example.com:8443/login</p><p>Visit https://example.com.</p>'
  '<p>Visit https://example.org, for more information.</p>'
  '<a href="https://duplicate.example.com">Duplicate</a><p>https://duplicate.example.com</p>'
  '<p>Contact user@example.com</p><p>This is not a URL: hello.world</p>',
  info=True, desc="Comprehensive page — log the full extraction for manual review.")

out = {
    "_readme": "Webpage URL-extraction sanity cases (GitHub Pages). Built by build_cases.py from "
               "webpage_url_extraction_test_cases(1).md + base-href resolution cases. Per case: "
               "'present' = absolute URLs that must appear in the antispam-log urlList; "
               "'presentTemplate' = same with {BASE} (full deploy base incl. /repo) / {ORIGIN} "
               "(scheme+host only) placeholders; 'absent' = must NOT appear; 'info'=true -> log only. "
               "generate.py wraps page.html into a static page under the given path.",
    "cases": cases,
}

with open(os.path.join(HERE, "cases.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)

print("wrote cases.json with %d cases" % len(cases))
assert_present = sum(1 for c in cases if c["present"] or c["presentTemplate"])
assert_absent = sum(1 for c in cases if c["absent"])
info = sum(1 for c in cases if c["info"])
print("  assert-present:%d  assert-absent:%d  info:%d" % (assert_present, assert_absent, info))
