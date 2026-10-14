# Sentrix AI: real threat-intelligence build

Static frontend (`index.html`, `backend.js`, `config.js`) + Node/Express API (`server/`) + Supabase (auth, Postgres, RLS).
The API verifies the user's Supabase token, then talks to Supabase **as that user**, so Row Level Security applies. No service-role key is used or needed.

## Windows setup (PowerShell)
1. Install Node.js LTS (nodejs.org, version 20 or newer). Extract the ZIP. In VS Code: File > Open Folder > the extracted folder, then Terminal > New Terminal.
2. `npm install`
3. Supabase (supabase.com, free project) > SQL Editor: run `supabase/migrations/001_init.sql`, then `002_real_intel.sql`.
4. Authentication > URL Configuration: Site URL and Redirect URL `http://localhost:3000`.
5. `Copy-Item .env.example .env`, then edit `.env`: set `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (Project Settings > API). Provider keys are optional.
6. Edit `config.js`: same Supabase URL and publishable key. `apiUrl` stays `http://localhost:8787`.
7. Terminal 1: `npm run dev` (API on 8787). Terminal 2: `npm run web` (site on 3000). Open http://localhost:3000
8. Test: create account, confirm email, sign in, run a scan, refresh, confirm it persists. Open `http://localhost:8787/api/providers/status` to see which providers are configured.

## Provider keys (optional; I could not re-check current terms, so confirm at each provider)
| Variable | Where | Notes |
|---|---|---|
| GOOGLE_SAFE_BROWSING_API_KEY | Google Cloud Console: enable Safe Browsing API, create a key | Free tier for non-commercial use, with quotas |
| VIRUSTOTAL_API_KEY | virustotal.com account, API key | Free public key is rate limited and non-commercial |
| URLHAUS_API_KEY | auth.abuse.ch (abuse.ch Auth-Key) | Free; abuse.ch has required an Auth-Key for API access |
| AI_PROVIDER_API_KEY, AI_MODEL, AI_PROVIDER_BASE_URL | Any OpenAI-compatible chat completions API | Pricing depends on provider |

Missing keys show as **Unavailable**. A provider error or timeout shows as **Failed**. Neither is ever treated as clean.

## API
Public: `GET /api/health`, `GET /api/providers/status`.
With `Authorization: Bearer <supabase access token>`: `POST /api/scans` {assetType: social|url|app, value, brand?, details?}, `GET /api/scans`, `GET /api/scans/:id`, `DELETE /api/scans/:id`, `GET /api/dashboard/stats`, `PATCH /api/investigations/:id` {status}, `POST /api/investigations/:id/notes` {note}.

## Behaviour
- Provider matches set the score (floor 75). Text heuristics alone are capped at 54. The AI explains the evidence; it does not set the score.
- If no provider ran, the result is labeled **Limited**.
- Social: URL reputation only; identity is never verified. App: name-only is inconclusive; a store URL or SHA-256 in "Optional details" triggers URL or VirusTotal file-hash lookups. No APK is downloaded.
- The server never fetches submitted URLs. It only sends them to provider APIs. Private and internal URLs are rejected.

## Deploy
- **Backend (Render):** web service from your private GitHub repo (`render.yaml` included). Set the env vars from `.env.example`. `FRONTEND_ORIGIN` is your Vercel URL with no trailing slash. Health check: `/api/health`.
- **Frontend (Vercel):** import the repo, Framework "Other", no build command. Set `apiUrl` in `config.js` to the Render https URL.
- **Supabase:** set Site URL and Redirect URL to the Vercel URL. Verify RLS by signing in as two users and confirming neither sees the other's scans.
- Never commit `.env`.

## Tests
`npm test` runs 18 tests with MOCKED providers (not live detections). Not covered: real RLS against a live database, and live provider calls.
