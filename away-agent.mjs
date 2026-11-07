// Course "while you're away" agent endpoint. Verifies the course signature, answers 2xx at once,
// then acts on the message and posts the reply to its replyUrl. No dependencies.
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import { readFileSync, appendFileSync, existsSync, writeFileSync } from 'node:fs';

const DIR = process.env.AWAY_DIR || '/data';
const PORT = Number(process.env.AWAY_PORT || 8931);
const ACTS = ['post_status', 'ack_alert', 'archive_report', 'purge_cache', 'release_hold', 'rotate_key'];

// The policy ships with the code; a copy in the data dir wins when present.
const policyFile = () =>
  existsSync(`${DIR}/policy.json`) ? `${DIR}/policy.json` : new URL('policy.json', import.meta.url).pathname;
const policy = () => JSON.parse(readFileSync(policyFile(), 'utf8'));
// The key comes from the environment in a container, from a file only when env is empty.
const signingKey = () =>
  (process.env.AWAY_SIGNING_KEY || '').trim() ||
  (existsSync(`${DIR}/signing-key.txt`) ? readFileSync(`${DIR}/signing-key.txt`, 'utf8').trim() : '');
const log = (o) => appendFileSync(`${DIR}/messages.jsonl`, JSON.stringify({ at: new Date().toISOString(), ...o }) + '\n');

export function checkSig(key, ts, sig, raw) {
  if (!key || !ts || !sig) return false;
  const want = 'sha256=' + createHmac('sha256', key).update(`${ts}.${raw}`).digest('hex');
  const a = Buffer.from(want), b = Buffer.from(String(sig));
  return a.length === b.length && timingSafeEqual(a, b);
}

// The check: the act named in the text decides the label; an unknown act is held for the human.
export function bucket(text, p = policy()) {
  const act = ACTS.find((a) => String(text || '').includes(a)) || null;
  return { act, label: act && p[act] === 'free' ? 'free' : 'gated' };
}

async function reply(replyUrl, text) {
  if (!replyUrl) return log({ kind: 'no-reply-url', text });
  try {
    const r = await fetch(replyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(15000),
    });
    log({ kind: 'reply', replyUrl, text, status: r.status, body: (await r.text()).slice(0, 400) });
  } catch (e) {
    log({ kind: 'reply-error', replyUrl, text, error: String(e) });
  }
}

async function handle(raw) {
  const body = JSON.parse(raw);
  const post = body.post || body;
  const { act, label } = bucket(post.text);
  const id = randomUUID();
  if (label === 'free') {
    await reply(post.replyUrl, `DONE ${act}. "${post.subject ?? ''}" handled.`);
    log({ kind: 'free', id, act, from: post.from, subject: post.subject, text: post.text });
  } else {
    const holds = existsSync(`${DIR}/holds.json`) ? JSON.parse(readFileSync(`${DIR}/holds.json`, 'utf8')) : [];
    holds.push({ id, act, at: new Date().toISOString(), from: post.from, subject: post.subject, text: post.text, replyUrl: post.replyUrl });
    writeFileSync(`${DIR}/holds.json`, JSON.stringify(holds, null, 1));
    await reply(post.replyUrl, `HELD ${act ?? 'unknown act'}. Needs my human's code. Request ${id}.`);
    log({ kind: 'hold', id, act, from: post.from, subject: post.subject, text: post.text });
  }
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    if (req.method === 'GET') { res.writeHead(200).end('away-agent up'); return; }
    if (req.url === '/__resolve' && req.socket.remoteAddress.includes('127.0.0.1')) {
      const { id, code } = JSON.parse(raw || '{}');
      const holds = existsSync(`${DIR}/holds.json`) ? JSON.parse(readFileSync(`${DIR}/holds.json`, 'utf8')) : [];
      const h = holds.find((x) => x.id === id);
      if (!h) { res.writeHead(404).end('no hold'); return; }
      res.writeHead(200).end('ok');
      reply(h.replyUrl, `DONE ${h.act}. Code ${code}.`).then(() => {
        writeFileSync(`${DIR}/holds.json`, JSON.stringify(holds.filter((x) => x.id !== id), null, 1));
      });
      return;
    }
    if (!checkSig(signingKey(), req.headers['x-course-timestamp'], req.headers['x-course-signature'], raw)) {
      log({ kind: 'reject', why: 'bad or missing signature', bytes: raw.length, keyLen: signingKey().length,
        headers: req.headers, raw: raw.slice(0, 400) });
      res.writeHead(401).end('bad signature');
      return;
    }
    res.writeHead(202).end('accepted'); // answer first, work after
    setImmediate(() => handle(raw).catch((e) => log({ kind: 'handle-error', error: String(e), raw: raw.slice(0, 500) })));
  });
});

if (process.argv.includes('--selftest')) {
  const p = { post_status: 'free', ack_alert: 'free', archive_report: 'free', purge_cache: 'gated', release_hold: 'gated', rotate_key: 'gated' };
  const assert = (c, m) => { if (!c) { console.error('FAIL', m); process.exit(1); } };
  assert(bucket('please purge_cache now', p).label === 'gated', 'purge_cache gated');
  assert(bucket('post_status: queue drained', p).label === 'free', 'post_status free');
  assert(bucket('something else entirely', p).label === 'gated', 'unknown act gated');
  const raw = '{"post":{"text":"x"}}', ts = '1';
  const good = 'sha256=' + createHmac('sha256', 'k').update(`${ts}.${raw}`).digest('hex');
  assert(checkSig('k', ts, good, raw), 'good sig');
  assert(!checkSig('k', ts, good, raw + ' '), 'tampered body');
  assert(!checkSig('k', '2', good, raw), 'tampered timestamp');
  assert(!checkSig('', ts, good, raw), 'no key');
  console.log('selftest ok');
} else {
  const bind = process.env.AWAY_BIND || '0.0.0.0';
  server.listen(PORT, bind, () => console.log(`away-agent on ${bind}:${PORT}`));
}
