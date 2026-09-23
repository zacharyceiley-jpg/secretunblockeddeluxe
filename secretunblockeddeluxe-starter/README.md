# Secret Unblocked Deluxe

The rebuilt Secret Unblocked platform.

## Current foundation

- Static GitHub Pages frontend
- Supabase Auth
- Real user profiles
- PostgreSQL-backed users
- Role system for users/moderators/admins
- Games database foundation
- Messages database foundation
- Row Level Security

## Files

- `index.html` — main application shell
- `css/style.css` — Deluxe styling
- `js/config.js` — public Supabase project configuration
- `js/app.js` — frontend logic

## Important

The Supabase publishable key may be used in browser code. Never put a Supabase secret/service-role key in this repository.

Database security is provided by Supabase Row Level Security.
