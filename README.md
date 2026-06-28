# ENV Vault Checker

A zero-trust `.env` secret scanner. Paste or upload a `.env` file and it flags
leaked credentials (AWS keys, Stripe keys, JWT secrets, database URLs, and more)
with severity ratings and remediation steps. **Your file never leaves the
browser** — all parsing and pattern matching happen client-side in JavaScript;
the backend only serves a static detection ruleset and never receives `.env`
content.

## Tech stack

- **Backend:** Spring Boot 3 on Java 17, packaged as a runnable JAR / Docker image (deployed to Render)
- **Frontend:** Vanilla HTML/CSS/JS, no build step (deployed to GitHub Pages)

## Project layout

```
env-vault-api/        Spring Boot service — serves GET /api/rules and GET /api/ping
env-vault-frontend/   Static client — the scanner UI and engine
```

## Run locally

**Backend** (serves the ruleset on `http://localhost:8080`):

```bash
cd env-vault-api
./mvnw spring-boot:run
```

Verify it's up:

```bash
curl http://localhost:8080/api/ping     # {"status":"ok"}
curl http://localhost:8080/api/rules    # the detection ruleset
```

**Frontend** (any static server works; VS Code Live Server is easiest):

```bash
cd env-vault-frontend
# open index.html with Live Server, or:
python3 -m http.server 5500
```

Then visit `http://localhost:5500`. The default `localhost:5500` /
`localhost:3000` origins are already allowed by the backend's CORS config.

## Live Demo

Coming soon — deploying in Phase 6.
