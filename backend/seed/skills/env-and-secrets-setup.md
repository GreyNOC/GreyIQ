---
name: env-and-secrets-setup
description: Discover required environment variables and create safe .env.example documentation
when: env, secrets, environment variables, dotenv, api key, token, credentials, .env.example
---
Use this playbook when the task involves environment variables, secrets,
credentials, API keys, tokens, or `.env.example`.

1. Discover required variables:
   - Search source, package scripts, docs, and config for `process.env`, `os.getenv`, `ENV`, and dotenv usage.
   - Group variables by frontend, backend, database, auth, provider, deployment, and optional features.
2. Create or update `.env.example` only:
   - Use placeholders such as `replace-me`, `your-api-key`, or empty values.
   - Never write real credentials, tokens, passwords, private keys, cookies, or production URLs.
   - Redact any discovered secret values in summaries and verification output.
3. Protect real env files:
   - Ensure `.env` is ignored when the project has a `.gitignore`.
   - Keep `.env.example` committed.
   - Do not echo real secret values to the UI or logs.
4. Document usage:
   - Explain which variables are required, optional, or deployment-only.
   - Mention where the app reads them and which service needs them.
   - Include safe local defaults such as `127.0.0.1` when applicable.
5. Verify:
   - Run the agent `verify` tool so `.env.example` is scanned for likely real secrets.
   - Run project checks when commands are enabled.
6. Rollback:
   - Restore the previous `.env.example` or `.gitignore`.
   - Do not delete a user's real `.env` unless they explicitly ask.
