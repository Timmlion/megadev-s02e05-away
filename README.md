# megadev-s02e05-away

Course "while you're away" agent endpoint (MEGA.dev S02E05).

- `POST /` — the course's message. Body `{"post":{"from","subject","text","replyUrl"}}`.
  Signature required: `sha256=` + hex HMAC-SHA256 of `<x-course-timestamp>.<raw body>`,
  keyed with `AWAY_SIGNING_KEY`. The endpoint answers `202` at once, then acts and posts
  `{"text": ...}` to `replyUrl`.
- `GET /` — health check, `200 away-agent up`.
- `POST /__resolve` (loopback only) — `{"id","code"}` closes a held act with the human's code.

The check: the act named in the text decides the label from `policy.json`. A free act is done
and reported; a gated act or an unknown act is held and logged in `holds.json`.

Environment: `AWAY_DIR` (default `/data`, holds `policy.json`, `holds.json`, `messages.jsonl`),
`AWAY_SIGNING_KEY` (preferred; falls back to `$AWAY_DIR/signing-key.txt`), `AWAY_PORT` (8931),
`AWAY_BIND` (0.0.0.0).

```sh
node away-agent.mjs --selftest   # HMAC accept/reject + act labelling
docker build -t away-agent . && docker run -p 8931:8931 -v away-data:/data -e AWAY_SIGNING_KEY=... away-agent
```

Policy in `policy.json` (B): `post_status`, `ack_alert`, `archive_report` free;
`purge_cache`, `release_hold`, `rotate_key` gated.
