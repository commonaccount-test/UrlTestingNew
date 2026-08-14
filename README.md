# URL-scan browser-resolution test site (GitHub Pages)

Live pages the antispam **URL scanner fetches** so we can verify it resolves relative
references (`<a href>`, `<base href>`, meta-refresh) the way a browser does — the behaviour
added in `source/change.txt`.

`cases.json` is the single source of truth: `generate.py` turns it into the static site, and
`src/zm_idc_antispam_sanity/spamSanity/URLBrowserResolutionSanity.java` reads it to know each
page's mail link and expected resolved URLs.

## How the pieces fit

1. Test sends a mail linking to `TEST_SITE_BASE/<page>`.
2. Backend URL scanner fetches that page and resolves the relative refs on it.
3. Test reads the extracted URLs from the antispam logs and asserts every browser-resolved
   absolute URL is present.

Deterministic cases carry an **absolute `<base href>`**, so their expected resolved URLs are
fixed no matter where you deploy. The meta-refresh case has no base and resolves against its
serving URL, so its expected value uses `{BASE}` (the deploy origin, including the `/<repo>`
path on GitHub Pages).

> Not included: a `Refresh:` response-header case and a real 30x-redirect case — GitHub Pages
> can't set response headers or emit a real 30x. Add them back only if hosting ever moves to a
> host that can (Netlify / Cloudflare Pages).

## Generate

```bash
cd urlscan-testsite
python3 generate.py            # -> ./docs
```

## Deploy on GitHub Pages

```bash
# Commit the urlscan-testsite/docs folder to your GitHub repo, then in the repo:
#   Settings -> Pages -> Build and deployment -> Deploy from a branch
#   Branch: main   Folder: /docs
```

Your site base becomes `https://<user>.github.io/<repo>` (note the repo path). The `.nojekyll`
file is emitted so Pages serves files verbatim.

Verify it's live (should return the page HTML, not 404):

```bash
curl -s https://<user>.github.io/<repo>/all-formats.html | head
```

## Run the test

`TEST_SITE_BASE` has no trailing slash.

```bash
java ... -Durlscan.site=https://<user>.github.io/<repo> \
         org.testng.TestNG <suite-including-URLBrowserResolutionSanity>
```

Prerequisites: backend `IS_RELATIVE_URL_HANDLING_ENABLED=true` for the org, and the backend must
be able to reach the deployed site over the public internet.
