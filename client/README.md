# Sentinel client

React + TypeScript + Vite front end. Authentication is handled by Clerk.

```bash
pnpm install   # or npm install
cp .env.example .env.local   # add VITE_CLERK_PUBLISHABLE_KEY
pnpm dev
```

Scripts: `dev`, `build`, `lint`, `preview`.

## Structure

- `src/styles/tokens.css` is the only place colours, type sizes, spacing and radii are defined.
- `src/index.css` holds global base styles, the shared button system and table base.
- Each page and component owns one CSS file next to it.
- Scan history and the inspection API are placeholders; see `src/data/sampleScans.ts`.
