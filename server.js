import express from 'express';
import cors from 'cors';
import { Pool } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const PORT = Number(process.env.PORT || 4242);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';

if (!DATABASE_URL) {
  console.error('DATABASE_URL tsy misy ao amin\'ny .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });
const uploadsDir = path.join(__dirname, 'uploads');

/* ================= Helpers ================= */
const ok = (res, data = null) => res.json({ data, error: null });
const fail = (res, status, message) => res.status(status).json({ data: null, error: { message } });

const uuidCols = new Set(['id', 'sender_id', 'receiver_id', 'user_id', 'msg_ids']);

function typedParam(col, val, op) {
  if (op === 'in' || op === 'includes') return Array.isArray(val) ? val : [val];
  return val;
}

function opSql(op) {
  switch (op) {
    case 'eq': return '=';
    case 'neq': return '<>';
    case 'gt': return '>';
    case 'gte': return '>=';
    case 'lt': return '<';
    case 'lte': return '<=';
    case 'in': return '= ANY';
    case 'includes': return '@>';
    default: return '=';
  }
}

function parseOr(str) {
  if (!str) return [];
  const clean = str.replace(/`/g, '');
  const groups = [];
  let i = 0;
  while (i < clean.length) {
    while (clean[i] === ',' || clean[i] === ' ') i++;
    if (i >= clean.length) break;
    if (clean.startsWith('and(', i)) {
      const end = findParen(clean, i + 4);
      if (end === -1) break;
      groups.push(parseAnd(clean.slice(i + 4, end)));
      i = end + 1;
    } else {
      const end = clean.indexOf(',', i);
      const token = clean.slice(i, end === -1 ? clean.length : end).trim();
      const cond = parseCond(token);
      if (cond) groups.push([cond]);
      i = end === -1 ? clean.length : end + 1;
    }
  }
  return groups;
}

function findParen(s, start) {
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseAnd(inner) {
  return inner.split(',').map(s => parseCond(s.trim())).filter(Boolean);
}

function parseCond(token) {
  const m = token.match(/^([A-Za-z0-9_.]+)\.(eq|neq|gt|gte|lt|lte|in|includes)\.(.*)$/);
  if (!m) return null;
  return { col: m[1], op: m[2], val: m[3] };
}

function buildWhere(filters = [], orStr = null, startN = 1, prefix = null) {
  const where = [];
  const params = [];
  let n = startN;
  const qname = (c) => prefix ? `${prefix}.${c}` : c;

  for (const { col, op, val } of filters) {
    let val2 = val;
    try { val2 = JSON.parse(val); } catch { /* keep string */ }
    const cast = uuidCols.has(col) ? '::uuid' : '';
    const q = qname(col);
    let sql;
    if (op === 'in') sql = `${q} ${opSql(op)} ANY($${n}${cast})`;
    else if (op === 'includes') sql = `${q} ${opSql(op)} $${n}${cast}`;
    else sql = `${q} ${opSql(op)} $${n}${cast}`;
    params.push(typedParam(col, val2, op));
    where.push(sql);
    n++;
  }

  for (const group of parseOr(orStr)) {
    const conds = group.map(c => {
      let v = c.val;
      try { v = JSON.parse(v); } catch { /* keep string */ }
      const cast = uuidCols.has(c.col) ? '::uuid' : '';
      params.push(typedParam(c.col, v, c.op));
      return `${qname(c.col)} ${opSql(c.op)} $${n++}${cast}`;
    });
    where.push(`(${conds.join(' AND ')})`);
  }

  return { where: where.join(' AND '), params };
}

/* ================= Auth ================= */
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });
}

function authUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    return { id: payload.sub, email: payload.email };
  } catch {
    return null;
  }
}

async function ensureProfileRow(id, email) {
  const exists = await pool.query('select 1 from profiles where id = $1', [id]);
  if (exists.rowCount === 0) {
    await pool.query(
      'insert into profiles (id, email, role) values ($1, $2, $3) on conflict (id) do nothing',
      [id, email, 'user']
    );
  }
}

/* ================= App ================= */
const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/api/storage', express.raw({ type: () => true, limit: '30mb' }));
app.use('/files', express.static(uploadsDir));

const otpCode = () => String(Math.floor(100000 + Math.random() * 900000));

/* -------- OTP / Signup -------- */
app.post('/api/auth/otp', async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  if (!email) return fail(res, 400, 'Email ilaina');
  const purpose = req.body?.purpose === 'reset' ? 'reset' : 'signup';
  const code = otpCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000);
  await pool.query(
    `insert into otp_codes (email, code, purpose, expires_at) values ($1,$2,$3,$4)
     on conflict (email) do update set code=$2, purpose=$3, expires_at=$4`,
    [email, code, purpose, expires]
  );
  ok(res, { user: null, devCode: code, message: 'Code voaray amin\'ny dev mode' });
});

app.post('/api/auth/otp/verify', async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.token || '');
  if (!email || !code) return fail(res, 400, 'Email sy code ilaina');

  const r = await pool.query(
    'select * from otp_codes where email = $1 and code = $2',
    [email, code]
  );
  if (r.rowCount === 0) return fail(res, 400, 'Code diso');
  const row = r.rows[0];
  if (new Date(row.expires_at) < new Date()) return fail(res, 400, 'Code efa lany daty');
  await pool.query('delete from otp_codes where email = $1', [email]);

  let user = await pool.query('select * from profiles where email = $1', [email]);
  if (user.rowCount === 0) {
    const id = crypto.randomUUID();
    await pool.query(
      'insert into profiles (id, email, role) values ($1, $2, $3) on conflict (id) do nothing',
      [id, email, 'user']
    );
    user = { rows: [{ id, email }] };
  }
  const u = user.rows[0];
  const token = signToken({ id: u.id, email: u.email });
  ok(res, { user: { id: u.id, email: u.email }, session: { access_token: token } });
});

app.post('/api/auth/login', async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  const password = req.body?.password || '';
  const r = await pool.query('select * from profiles where email = $1', [email]);
  if (r.rowCount === 0 || !r.rows[0].password_hash) {
    return fail(res, 400, 'Email ou mot de passe incorrect');
  }
  const okPw = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!okPw) return fail(res, 400, 'Email ou mot de passe incorrect');
  const u = r.rows[0];
  const token = signToken({ id: u.id, email: u.email });
  await pool.query("update profiles set status='actif', last_seen=now() where id=$1", [u.id]);
  ok(res, { user: { id: u.id, email: u.email }, session: { access_token: token } });
});

app.post('/api/auth/password', async (req, res) => {
  const user = authUser(req);
  if (!user) return fail(res, 401, 'Tsy connecté');
  const password = req.body?.password || '';
  if (!password || password.length < 6) return fail(res, 400, 'Mot de passe kely loatra (min 6)');
  const hash = await bcrypt.hash(password, 10);
  await pool.query('update profiles set password_hash = $1 where id = $2', [hash, user.id]);
  ok(res, { user: { id: user.id, email: user.email } });
});

app.get('/api/auth/me', (req, res) => {
  const user = authUser(req);
  if (!user) return ok(res, { user: null });
  ok(res, { user });
});

app.post('/api/auth/logout', (req, res) => ok(res, {}));

/* -------- Generic table API -------- */
app.get('/api/:table', async (req, res) => {
  const table = req.params.table;
  const { filters, or, order, limit, single } = req.query;
  const f = filters ? (Array.isArray(filters) ? filters.flatMap(x => x.split(';;')) : String(filters).split(';;')) : [];
  const parsed = f.map(s => {
    const idx = s.indexOf('|', s.indexOf('|') + 1);
    const col = s.slice(0, s.indexOf('|'));
    const rest = s.slice(s.indexOf('|') + 1);
    const op = rest.slice(0, rest.indexOf('|'));
    const val = rest.slice(rest.indexOf('|') + 1);
    return { col, op, val };
  });

  const { where, params } = buildWhere(parsed, or, 1, table === 'payments' ? 'p' : null);
  let orderSql = '';
  if (order) {
    const parts = Array.isArray(order) ? order : [order];
    orderSql = parts.map(o => {
      const [col, dir] = o.split(':');
      const q = table === 'payments' ? `p.${col}` : col;
      return `${q} ${dir === 'desc' ? 'DESC' : 'ASC'}`;
    }).join(', ');
  }
  let sql = `select * from ${table}`;
  if (where) sql += ` where ${where}`;
  if (orderSql) sql += ` order by ${orderSql}`;
  if (limit) sql += ` limit ${Number(limit)}`;

  let rows;
  if (table === 'payments') {
    const joins = `select p.*, row_to_json(pr) as _profile
      from payments p left join profiles pr on pr.id = p.user_id`;
    sql = sql.replace('select * from payments', joins);
    const r = await pool.query(sql, params);
    rows = r.rows.map(x => ({
      ...x,
      profiles: { first_name: x._profile?.first_name, last_name: x._profile?.last_name }
    }));
    rows.forEach(x => { delete x._profile; });
  } else {
    rows = (await pool.query(sql, params)).rows;
  }

  if (single === '1' || single === 'true') return ok(res, rows[0] ?? null);
  ok(res, rows);
});

app.post('/api/:table', async (req, res) => {
  const table = req.params.table;
  const rows = Array.isArray(req.body) ? req.body : [req.body];
  const out = [];
  for (const row of rows) {
    const keys = Object.keys(row).filter(k => k !== 'id');
    const cols = ['id'].concat(keys);
    const vals = [row.id || crypto.randomUUID()].concat(keys.map(k => row[k]));
    const qs = cols.map((c, i) => `$${i + 1}`).join(', ');
    const r = await pool.query(`insert into ${table} (${cols.join(', ')}) values (${qs}) returning *`, vals);
    out.push(r.rows[0]);
  }
  ok(res, out);
});

app.post('/api/:table/upsert', async (req, res) => {
  const table = req.params.table;
  const row = req.body;
  if (!row?.id) return fail(res, 400, 'id ilaina ho an\'ny upsert');

  const existing = await pool.query(`select * from ${table} where id = $1`, [row.id]);
  if (existing.rowCount > 0) {
    const keys = Object.keys(row).filter(k => k !== 'id');
    if (keys.length === 0) return ok(res, existing.rows[0]);
    const setSql = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
    const r = await pool.query(
      `update ${table} set ${setSql} where id = $${keys.length + 1} returning *`,
      keys.map(k => row[k]).concat([row.id])
    );
    ok(res, r.rows[0]);
  } else {
    const keys = Object.keys(row);
    const qs = keys.map((k, i) => `$${i + 1}`).join(', ');
    const r = await pool.query(
      `insert into ${table} (${keys.join(', ')}) values (${qs}) returning *`,
      keys.map(k => row[k])
    );
    ok(res, r.rows[0]);
  }
});

app.patch('/api/:table', async (req, res) => {
  const table = req.params.table;
  const { filters, or } = req.query;
  const f = filters ? (Array.isArray(filters) ? filters.flatMap(x => x.split(';;')) : String(filters).split(';;')) : [];
  const parsed = f.map(s => {
    const first = s.indexOf('|');
    const col = s.slice(0, first);
    const rest = s.slice(first + 1);
    const second = rest.indexOf('|');
    const op = rest.slice(0, second);
    const val = rest.slice(second + 1);
    return { col, op, val };
  });

  const body = req.body || {};
  const keys = Object.keys(body).filter(k => k !== 'id');
  if (keys.length === 0) return ok(res, null);

  const { where, params } = buildWhere(parsed, or, keys.length + 1);
  if (!where) return fail(res, 400, 'Filtre ilaina ho an\'ny update');

  if (table === 'messages') {
    if (body.read === true || body.read === 'true') {
      body.seen_at = new Date().toISOString();
      body.is_seen = true;
    }
  }

  const setSql = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const r = await pool.query(
    `update ${table} set ${setSql} where ${where} returning *`,
    keys.map(k => body[k]).concat(params)
  );
  ok(res, r.rows);
});

app.delete('/api/:table', async (req, res) => {
  const table = req.params.table;
  const { filters } = req.query;
  const f = filters ? (Array.isArray(filters) ? filters.flatMap(x => x.split(';;')) : String(filters).split(';;')) : [];
  const parsed = f.map(s => {
    const first = s.indexOf('|');
    const col = s.slice(0, first);
    const rest = s.slice(first + 1);
    const second = rest.indexOf('|');
    const op = rest.slice(0, second);
    const val = rest.slice(second + 1);
    return { col, op, val };
  });
  const { where, params } = buildWhere(parsed);
  if (!where) return fail(res, 400, 'Filtre ilaina');
  await pool.query(`delete from ${table} where ${where}`, params);
  ok(res, null);
});

/* -------- RPC -------- */
app.post('/api/rpc/:name', async (req, res) => {
  const name = req.params.name;
  if (name === 'add_deleted_by') {
    const { msg_ids, user_id } = req.body || {};
    await pool.query('select add_deleted_by($1, $2)', [msg_ids, user_id]);
    return ok(res, null);
  }
  fail(res, 404, 'RPC tsy fantatra');
});

/* -------- Storage -------- */
app.post('/api/storage/:bucket', async (req, res) => {
  const bucket = req.params.bucket;
  const filePath = String(req.query.path || crypto.randomUUID());
  const safe = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const dest = path.join(uploadsDir, bucket, safe);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, req.body);
  ok(res, { id: safe, path: safe, publicUrl: `${APP_URL}/files/${bucket}/${safe}` });
});

app.delete('/api/storage/:bucket', async (req, res) => {
  const bucket = req.params.bucket;
  const filePath = String(req.query.path || '');
  const safe = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const dest = path.join(uploadsDir, bucket, safe);
  fs.rmSync(dest, { force: true });
  ok(res, null);
});

/* -------- AI exercises -------- */
app.post('/api/ai/exercises', async (req, res) => {
  const { level = 'A1', mode = 'exercises', lang = 'fr' } = req.body || {};
  try {
    if (GROQ_API_KEY) {
      const target = lang === 'fr' ? 'Français' : 'English';
      const isVocab = mode === 'vocab';
      const count = isVocab ? 20 : 10;
      const systemPrompt = isVocab
        ? `Tu es un professeur de ${target}. Génère exactement ${count} mots de vocabulaire au format JSON pur. Niveau: ${level}. Format EXACT: {"exercises":[{"exercise_type":"vocab","question":"...","choices":["..."],"answer":"..."}]}. Mots en ${target} seulement.`
        : `Tu es un professeur de ${target}. Génère ${count} exercices mixte (quiz + speaking) au format JSON pur. Niveau: ${level}. Format EXACT: {"exercises":[{"exercise_type":"quiz","question":"...","choices":["..."],"answer":"..."},{"exercise_type":"speaking","question":"...","choices":[],"answer":"..."}]}. Questions et réponses en ${target} seulement.`;
      const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: `Level ${level}, mode ${mode}.` }
          ],
          temperature: 0.5,
          response_format: { type: 'json_object' }
        })
      });
      const aiData = await resp.json();
      const content = aiData.choices?.[0]?.message?.content;
      if (content) {
        const parsed = JSON.parse(content);
        return ok(res, parsed);
      }
    }
    ok(res, { exercises: fallbackExercises(level, mode, lang) });
  } catch (e) {
    ok(res, { exercises: fallbackExercises(level, mode, lang) });
  }
});

function fallbackExercises(level, mode, lang) {
  const l = lang === 'en' ? 'en' : 'fr';
  const mk = (type, q, choices, answer) => ({ exercise_type: type, question: q, choices, answer });
  if (mode === 'vocab') {
    const fr = [
      mk('vocab', 'Apple', ['La pomme', 'La poire', 'Le raisin', 'La banane'], 'La pomme'),
      mk('vocab', 'Book', ['Le stylo', 'Le livre', 'Le cahier', 'La table'], 'Le livre'),
      mk('vocab', 'Water', ['Le lait', 'Le vin', 'Leau', 'Le café'], 'Leau'),
      mk('vocab', 'House', ['La maison', 'La voiture', 'Lécole', 'Le magasin'], 'La maison')
    ];
    const en = [
      mk('vocab', 'Pomme', ['Apple', 'Pear', 'Grape', 'Banana'], 'Apple'),
      mk('vocab', 'Livre', ['Pen', 'Book', 'Notebook', 'Table'], 'Book'),
      mk('vocab', 'Eau', ['Milk', 'Wine', 'Water', 'Coffee'], 'Water'),
      mk('vocab', 'Maison', ['House', 'Car', 'School', 'Shop'], 'House')
    ];
    return (l === 'fr' ? en : fr).slice(0, 10);
  }
  const fr = [
    mk('quiz', 'What is the plural of "child"?', ['Children', 'Childs', 'Childes', 'Child'], 'Children'),
    mk('speaking', 'Introduce yourself: "My name ..."', [], 'My name is...'),
    mk('quiz', 'She ___ to school every day.', ['go', 'goes', 'going', 'gone'], 'goes'),
    mk('speaking', 'Say: "How are you today?"', [], 'How are you today?')
  ];
  const en = [
    mk('quiz', 'Quel est le pluriel de "child"?', ['Children', 'Childs', 'Childes', 'Child'], 'Children'),
    mk('speaking', 'Présentez-vous : "My name ..."', [], 'My name is...'),
    mk('quiz', 'She ___ to school every day.', ['go', 'goes', 'going', 'gone'], 'goes'),
    mk('speaking', 'Dites : "How are you today?"', [], 'How are you today?')
  ];
  return (l === 'fr' ? fr : en).slice(0, 6);
}

app.use(function errHandler(err, req, res, next) {
  console.error(err);
  if (!res.headersSent) fail(res, 500, err.message);
});

/* ============================================================
   FRONT WEB + TÉLÉCHARGEMENT APK
   (public/ : app build velezina amin'ny zotran'ny fàrfàny)
   ============================================================ */
const publicDir = path.join(__dirname, 'public');
const apkPath = path.join(publicDir, 'apk', 'GasyTalk.apk');

app.get('/apk', (req, res) => {
  if (fs.existsSync(apkPath)) {
    res.download(apkPath, 'GasyTalk.apk');
  } else {
    fail(res, 404, 'APK tsy mbola napetraka');
  }
});

app.use(express.static(publicDir, { index: false }));

app.get('/', (req, res) => {
  const index = path.join(publicDir, 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  res.type('html').send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>GasyTalk API</title></head><body style="font-family:sans-serif;text-align:center;padding:40px">
  <h1>✅ GasyTalk API serveur mandeha</h1>
  <p><a href="/apk">📲 Télécharger l'APK GasyTalk</a></p>
  <p><a href="/api/auth/me">Vérifier API</a></p></body></html>`);
});

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  if (req.path.startsWith('/api') || req.path.startsWith('/files')) return next();
  const index = path.join(publicDir, 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  next();
});

app.listen(PORT, () => {
  console.log(`GasyTalk API listen on ${APP_URL}`);
});