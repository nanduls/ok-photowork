# OK.PHOTOWORK

Photography site with an admin editor, private client galleries, star ratings and notes.
Runs on Cloudflare Pages.

- `index.html` is the site.
- `functions/api/[[path]].js` is the backend (Cloudflare Pages Functions).

## One-time Cloudflare setup
1. Workers & Pages > KV > Create a namespace (for example `ok-photowork`).
2. R2 > Create a bucket (for example `ok-photowork-photos`). R2 needs billing details on file; the free tier is generous.
3. Pages project > Settings > Bindings (Functions):
   - Add KV namespace binding. Variable name: `SITE`. Pick the namespace from step 1.
   - Add R2 bucket binding. Variable name: `PHOTOS`. Pick the bucket from step 2.
4. Pages project > Settings > Variables and Secrets (Production), add as Secrets:
   - `ADMIN_PASSWORD` : the password you will use to sign in to the admin page.
   - `SESSION_SECRET` : a long random string (40+ characters).
5. Redeploy (Deployments > Retry deployment) so the bindings take effect.

## Using it
- Admin: open `https://YOUR-SITE/#admin` and sign in with `ADMIN_PASSWORD`.
- Clients: open `https://YOUR-SITE/#client` and sign in with the ID and password you set for them.
- Client photos are private. They are only served to the client who owns them and to the admin.
