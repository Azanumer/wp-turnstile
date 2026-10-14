# WP Turnstile

Adds [Cloudflare Turnstile](https://www.cloudflare.com/application-services/products/turnstile/) — the privacy-friendly, often invisible CAPTCHA alternative — to WordPress forms. One plugin file, no JavaScript bundled, no tracking cookies on your visitors.

## Protected forms

| Form | Hook point | Notes |
|---|---|---|
| Login | `login_form` + `authenticate` | Verified only when credentials are actually submitted (empty-login probes bypass it, avoiding breakage of external login tools) |
| Registration | `register_form` + `registration_errors` | Error shows inline on the register page |
| Lost password | `lostpassword_form` + `lostpassword_post` | Error shows inline on the lost-password page |
| Comments | `comment_form_after` + `preprocess_comment` | Guests only; logged-in users are trusted. Failed check → `wp_die` with a back link |

Each form can be toggled independently from the settings page.

## How verification works

1. The official Cloudflare widget script (`challenges.cloudflare.com/turnstile/v0/api.js`) is enqueued only on pages where a widget renders.
2. On submit, the token in `cf-turnstile-response` is sent server-side to Cloudflare's `siteverify` endpoint with your secret key and the visitor's IP.
3. Fail-closed: if the token is missing or verification fails, the action is rejected.

## Install

1. Get free keys: Cloudflare Dashboard → **Turnstile** → add a site. For testing, Cloudflare documents public test keys:
   - Site key: `1x00000000000000000000AA`
   - Secret key: `1x0000000000000000000000000000000AA`
2. Copy `wp-turnstile.php` and `uninstall.php` into `wp-content/plugins/wp-turnstile/`
3. Activate, go to **Settings → Turnstile**, paste keys, choose which forms to protect, enable.

## Widget theme

`auto` (follows the visitor's OS setting), `light`, or `dark` — passed straight through to the widget via `data-theme`.

## Notes

- Logged-in users skip the comment-form challenge entirely.
- The secret key is stored as plain text in the option — standard for WP plugins; keep your database backups private.

MIT licensed. Contributions welcome.
