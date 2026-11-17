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

## Using it
- Admin: open `https://YOUR-SITE/#admin` and sign in with `ADMIN_PASSWORD`.
- Clients: open `https://YOUR-SITE/#client` and sign in with the ID and password you set for them.
- Client photos are private. They are only served to the client who owns them and to the admin.
