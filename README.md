# Website Tech Stack Profiler, On-Page SEO Auditor & Security Headers API (Cloudflare Worker)

Real-time Website Technology Fingerprinting, On-Page SEO Auditor (`0-100` score), Schema.org JSON-LD Extractor, and HTTP Security Header Inspector running on **Cloudflare Workers Free Tier** (`$0/month` hosting) for **RapidAPI Hub**.

## Endpoints
- `GET|POST /v1/audit?url=https://...` — Full SEO score (`0-100`), meta/OpenGraph/Twitter tags, H1/H2 structure, missing image alt count, Schema.org types, detected Tech Stack (`Next.js`, `React`, `Shopify`, `WordPress`, `GA4`, `HubSpot`, `Stripe`, `Segment`, `PostHog`, etc.), and HTTP Security Headers (`HSTS`, `CSP`, `X-Frame-Options`).
- `GET /v1/health` — Service health check.
