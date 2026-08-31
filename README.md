# SAREE Premium — Turso Edition

Production-oriented Express + Turso + Groq saree store. All application data, including product images and logo data, is stored in Turso as text/base64 so the service does not depend on Render's ephemeral filesystem.

## Render
- Root Directory: blank
- Build: `npm install`
- Start: `npm start`

## Required environment variables
- `TURSO_DATABASE_URL`
- `TURSO_AUTH_TOKEN`
- `ADMIN_PASSWORD` (only used for the first admin account; change it from Admin > Security)
- `GROQ_API_KEY`
- `GROQ_MODEL` optional

Never commit real tokens or keys.


## Branding
The default SAREE floral emblem is embedded directly as inline SVG in `public/index.html` and `admin/index.html`; no logo image file is required. If an admin uploads a custom logo, that uploaded logo is stored in Turso and takes precedence on the storefront.

## Persistence
Products, orders, agents, store settings, chatbot settings, password hash, and uploaded product/logo images are persisted in Turso. The Render filesystem is not used as the source of truth.
