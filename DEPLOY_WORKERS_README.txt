FAITH CLINIC — Cloudflare Workers deployment package

This package converts the Pages Function into a standalone Worker and serves website files through Workers Static Assets. It does not require a functions folder.

BEFORE DEPLOYING
1. Extract this ZIP to a folder on your computer.
2. Open wrangler.jsonc and replace BOTH placeholders with the exact NAME and ID of your EXISTING Cloudflare D1 database. Keep the binding as DB. Do not create a new database if your existing one contains members.
3. Install Node.js if needed. Open a terminal in the extracted folder.
4. Run: npx wrangler login
5. Run: npx wrangler deploy
6. The deployment URL is shown by Wrangler. First test /api/me (expect 401 if not signed in), then registration via the website and login.

IMPORTANT
- Deployment creates/updates the Worker named faith-clinic-membership; it does NOT automatically replace the Worker or custom domain currently serving your live website. Verify on the workers.dev URL first, then configure the intended custom domain/route after testing.
- The database tables in schema.sql must already exist. If your D1 is empty, apply schema.sql via D1 Console; do not blindly apply it to an existing populated database.
- Do not upload schema.sql or this README to the public website. They are outside public/.
- Use a staging Worker for tests; do not register test users on production unless intended.
- Review anti-abuse/rate limits and authentication security before a public launch.
