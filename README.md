# OK.PHOTOWORK

Photography site with an admin editor, private client galleries, star ratings and notes.
Runs as a Cloudflare Worker with static assets.

- `public/index.html` is the site (served as static assets).
- `src/worker.js` is the backend. It only handles `/api/*` requests.
- `wrangler.jsonc` is the Worker config (assets, KV and R2 bindings).

## Deploy
The deploy command is `npx wrangler deploy`.

On the first deploy Wrangler creates the KV namespace (binding `SITE`) and the R2 bucket
(binding `PHOTOS`) automatically. R2 needs billing details on file; the free tier is generous.
If you already have a namespace or bucket, put its `id` / `bucket_name` in `wrangler.jsonc`.

## One-time secrets
Worker > Settings > Variables and Secrets, add as **Secrets**:
- `ADMIN_PASSWORD` : the password you will use to sign in to the admin page.
- `SESSION_SECRET` : a long random string (40+ characters).

Or from a terminal: `npx wrangler secret put ADMIN_PASSWORD` and `npx wrangler secret put SESSION_SECRET`.

## Pages
- Home, Portfolio, Journal, **About** (intro, values and the photographer team) and **Contact** (booking form) are separate pages.
- Admin > **Team**: add, reorder or remove team members. Each has a photo, role, short bio and comma-separated skills. Every member gets a "Book <name>" button that opens the Contact page with that photographer selected.
- Admin > **Bookings**: every request from the Contact form. Filter by status (New, Confirmed, Done, Cancelled), change the status, add a private note, or delete. A badge on the tab counts new requests.

## Bookings
Booking requests are stored in the `SITE` KV namespace under keys starting with `bk:` (newest first).
The public form posts to `POST /api/booking`. It checks the fields, ignores bots (hidden honeypot field) and
allows 5 requests per connection per hour. There is no email notification, so check Admin > Bookings
(the customer can also message you on WhatsApp from the confirmation screen).

## Using it
- Admin: open `https://YOUR-SITE/#admin` and sign in with `ADMIN_PASSWORD`.
- Clients: open `https://YOUR-SITE/#client` and sign in with the ID and password you set for them.
- Client photos are private. They are only served to the client who owns them and to the admin.
