const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Database (Postgres / Neon) ────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const query = async (text, params) => (await pool.query(text, params)).rows;
const one = async (text, params) => (await query(text, params))[0] || null;

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS households (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      invite_code TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      color TEXT DEFAULT '#3b82f6',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS members (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      name TEXT NOT NULL,
      color TEXT DEFAULT '#3b82f6',
      user_id TEXT REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      created_by TEXT REFERENCES users(id),
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      date TEXT NOT NULL,
      is_recurring INTEGER DEFAULT 0,
      is_fixed INTEGER DEFAULT 0,
      notes TEXT DEFAULT '',
      member_id TEXT REFERENCES members(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      name TEXT NOT NULL,
      monthly_limit REAL DEFAULT 0,
      color TEXT DEFAULT '#6b7280'
    );

    CREATE TABLE IF NOT EXISTS goals (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      name TEXT NOT NULL,
      target_amount REAL NOT NULL,
      current_amount REAL DEFAULT 0,
      deadline TEXT,
      color TEXT DEFAULT '#3b82f6'
    );

    CREATE TABLE IF NOT EXISTS bills (
      id TEXT PRIMARY KEY,
      household_id TEXT NOT NULL REFERENCES households(id),
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      amount REAL NOT NULL,
      due_date TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      is_recurring INTEGER DEFAULT 0,
      member_id TEXT REFERENCES members(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

// ─── Helpers ────────────────────────────────────────────────
const uid = () => crypto.randomUUID();
const wrap = fn => async (req, res, next) => { try { await fn(req, res, next); } catch(e) { console.error(e); res.status(500).json({ error: e.message || 'Erro interno do servidor' }); } };
const MEMBER_COLORS = ['#3b82f6','#ec4899','#10b981','#f97316','#a855f7','#e54848','#eab308','#06b6d4'];
const DEFAULT_CATS = [
  { name: 'Alimentação', limit: 800,  color: '#f97316' },
  { name: 'Transporte',  limit: 400,  color: '#3b82f6' },
  { name: 'Moradia',     limit: 1500, color: '#a855f7' },
  { name: 'Lazer',       limit: 300,  color: '#ec4899' },
  { name: 'Saúde',       limit: 200,  color: '#10b981' },
  { name: 'Outros',      limit: 500,  color: '#6b7280' },
];

// Field mappers (snake_case DB → camelCase frontend)
const mapTx  = t => ({ ...t, isRecurring: !!t.is_recurring, isFixed: !!t.is_fixed, memberId: t.member_id || null });
const mapCat = c => ({ id: c.id, name: c.name, limit: c.monthly_limit, color: c.color });
const mapGoal= g => ({ id: g.id, name: g.name, targetAmount: g.target_amount, currentAmount: g.current_amount, deadline: g.deadline, color: g.color });
const mapBill= b => ({ ...b, dueDate: b.due_date, isRecurring: !!b.is_recurring, memberId: b.member_id || null });
const monthPattern = (year, month) => `${year}-${String(month).padStart(2,'0')}-%`;

// ─── Auth middleware ─────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  const session = await one('SELECT * FROM sessions WHERE token = $1 AND expires_at > $2', [token, new Date().toISOString()]);
  if (!session) return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  const user = await one('SELECT * FROM users WHERE id = $1', [session.user_id]);
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
  req.user = user;
  req.hid  = user.household_id;
  next();
}

// ─── AUTH ────────────────────────────────────────────────────
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password, householdName, inviteCode } = req.body;
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  if (await one('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]))
    return res.status(400).json({ error: 'E-mail já cadastrado' });

  let householdId;
  if (inviteCode?.trim()) {
    const hh = await one('SELECT * FROM households WHERE invite_code = $1', [inviteCode.trim().toUpperCase()]);
    if (!hh) return res.status(400).json({ error: 'Código de convite inválido' });
    householdId = hh.id;
  } else {
    if (!householdName?.trim()) return res.status(400).json({ error: 'Nome da casa é obrigatório' });
    householdId = uid();
    const invite = crypto.randomBytes(3).toString('hex').toUpperCase();
    await query('INSERT INTO households (id, name, invite_code) VALUES ($1, $2, $3)', [householdId, householdName.trim(), invite]);
    for (const c of DEFAULT_CATS)
      await query('INSERT INTO categories (id, household_id, name, monthly_limit, color) VALUES ($1, $2, $3, $4, $5)', [uid(), householdId, c.name, c.limit, c.color]);
  }

  const countRow = await one('SELECT count(*) as c FROM members WHERE household_id = $1', [householdId]);
  const count = parseInt(countRow.c, 10);
  const color = MEMBER_COLORS[count % MEMBER_COLORS.length];
  const passwordHash = await bcrypt.hash(password, 10);
  const userId = uid();

  await query('INSERT INTO users (id, household_id, name, email, password_hash, color) VALUES ($1, $2, $3, $4, $5, $6)', [userId, householdId, name.trim(), email.toLowerCase(), passwordHash, color]);
  await query('INSERT INTO members (id, household_id, name, color, user_id) VALUES ($1, $2, $3, $4, $5)', [uid(), householdId, name.trim(), color, userId]);

  const token = crypto.randomBytes(32).toString('hex');
  await query('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)', [token, userId, new Date(Date.now() + 30*86400*1000).toISOString()]);

  const hh = await one('SELECT * FROM households WHERE id = $1', [householdId]);
  res.json({ token, user: { id: userId, name: name.trim(), email: email.toLowerCase(), color, householdId, householdName: hh.name, inviteCode: hh.invite_code } });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { email, password } = req.body;
  const user = await one('SELECT * FROM users WHERE email = $1', [email?.toLowerCase()]);
  if (!user || !await bcrypt.compare(password, user.password_hash))
    return res.status(400).json({ error: 'E-mail ou senha incorretos' });

  const token = crypto.randomBytes(32).toString('hex');
  await query('INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)', [token, user.id, new Date(Date.now() + 30*86400*1000).toISOString()]);
  const hh = await one('SELECT * FROM households WHERE id = $1', [user.household_id]);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, color: user.color, householdId: user.household_id, householdName: hh?.name, inviteCode: hh?.invite_code } });
}));

app.post('/api/auth/logout', auth, wrap(async (req, res) => {
  await query('DELETE FROM sessions WHERE token = $1', [req.headers.authorization?.replace('Bearer ', '')]);
  res.json({ ok: true });
}));

app.get('/api/auth/me', auth, wrap(async (req, res) => {
  const hh = await one('SELECT * FROM households WHERE id = $1', [req.hid]);
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email, color: req.user.color, householdId: req.hid, householdName: hh?.name, inviteCode: hh?.invite_code });
}));

// ─── MEMBERS ─────────────────────────────────────────────────
app.get('/api/members', auth, wrap(async (req, res) =>
  res.json(await query('SELECT * FROM members WHERE household_id = $1', [req.hid]))
));

app.post('/api/members', auth, wrap(async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nome obrigatório' });
  const id = uid();
  await query('INSERT INTO members (id, household_id, name, color) VALUES ($1, $2, $3, $4)', [id, req.hid, name.trim(), color || '#3b82f6']);
  res.json({ id, name: name.trim(), color: color || '#3b82f6', household_id: req.hid });
}));

app.put('/api/members/:id', auth, wrap(async (req, res) => {
  const { name, color } = req.body;
  await query('UPDATE members SET name=$1, color=$2 WHERE id=$3 AND household_id=$4', [name?.trim(), color, req.params.id, req.hid]);
  res.json({ ok: true });
}));

app.delete('/api/members/:id', auth, wrap(async (req, res) => {
  await query('UPDATE transactions SET member_id=NULL WHERE member_id=$1', [req.params.id]);
  await query('UPDATE bills SET member_id=NULL WHERE member_id=$1', [req.params.id]);
  await query('DELETE FROM members WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  res.json({ ok: true });
}));

// ─── TRANSACTIONS ─────────────────────────────────────────────
app.get('/api/transactions', auth, wrap(async (req, res) => {
  let q = 'SELECT * FROM transactions WHERE household_id = $1';
  const p = [req.hid];
  if (req.query.year && req.query.month) {
    p.push(monthPattern(req.query.year, req.query.month));
    q += ` AND date LIKE $${p.length}`;
  }
  q += ' ORDER BY date DESC, created_at DESC';
  res.json((await query(q, p)).map(mapTx));
}));

app.post('/api/transactions', auth, wrap(async (req, res) => {
  const { type, description, amount, category, date, isRecurring, isFixed, notes, memberId } = req.body;
  const id = uid();
  await query(
    'INSERT INTO transactions (id,household_id,created_by,type,description,amount,category,date,is_recurring,is_fixed,notes,member_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
    [id, req.hid, req.user.id, type, description, amount, category, date, isRecurring?1:0, isFixed?1:0, notes||'', memberId||null]
  );
  res.json({ id });
}));

app.put('/api/transactions/:id', auth, wrap(async (req, res) => {
  const { type, description, amount, category, date, isRecurring, isFixed, notes, memberId } = req.body;
  await query(
    'UPDATE transactions SET type=$1,description=$2,amount=$3,category=$4,date=$5,is_recurring=$6,is_fixed=$7,notes=$8,member_id=$9 WHERE id=$10 AND household_id=$11',
    [type, description, amount, category, date, isRecurring?1:0, isFixed?1:0, notes||'', memberId||null, req.params.id, req.hid]
  );
  res.json({ ok: true });
}));

app.delete('/api/transactions/:id', auth, wrap(async (req, res) => {
  await query('DELETE FROM transactions WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  res.json({ ok: true });
}));

// ─── CATEGORIES ──────────────────────────────────────────────
app.get('/api/categories', auth, wrap(async (req, res) =>
  res.json(await query('SELECT id, name, monthly_limit as "limit", color FROM categories WHERE household_id=$1', [req.hid]))
));

app.post('/api/categories', auth, wrap(async (req, res) => {
  const { name, limit, color } = req.body;
  const id = uid();
  await query('INSERT INTO categories (id,household_id,name,monthly_limit,color) VALUES ($1,$2,$3,$4,$5)', [id, req.hid, name, limit||0, color||'#6b7280']);
  res.json({ id });
}));

app.put('/api/categories/:id', auth, wrap(async (req, res) => {
  const { name, limit, color } = req.body;
  await query('UPDATE categories SET name=$1,monthly_limit=$2,color=$3 WHERE id=$4 AND household_id=$5', [name, limit||0, color, req.params.id, req.hid]);
  res.json({ ok: true });
}));

app.delete('/api/categories/:id', auth, wrap(async (req, res) => {
  await query('DELETE FROM categories WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  res.json({ ok: true });
}));

// ─── GOALS ───────────────────────────────────────────────────
app.get('/api/goals', auth, wrap(async (req, res) =>
  res.json((await query('SELECT * FROM goals WHERE household_id=$1', [req.hid])).map(mapGoal))
));

app.post('/api/goals', auth, wrap(async (req, res) => {
  const { name, targetAmount, currentAmount, deadline, color } = req.body;
  const id = uid();
  await query('INSERT INTO goals (id,household_id,name,target_amount,current_amount,deadline,color) VALUES ($1,$2,$3,$4,$5,$6,$7)', [id, req.hid, name, targetAmount, currentAmount||0, deadline||null, color||'#3b82f6']);
  res.json({ id });
}));

app.put('/api/goals/:id', auth, wrap(async (req, res) => {
  const { name, targetAmount, currentAmount, deadline, color } = req.body;
  await query('UPDATE goals SET name=$1,target_amount=$2,current_amount=$3,deadline=$4,color=$5 WHERE id=$6 AND household_id=$7', [name, targetAmount, currentAmount||0, deadline||null, color, req.params.id, req.hid]);
  res.json({ ok: true });
}));

app.delete('/api/goals/:id', auth, wrap(async (req, res) => {
  await query('DELETE FROM goals WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  res.json({ ok: true });
}));

// ─── BILLS ───────────────────────────────────────────────────
app.get('/api/bills', auth, wrap(async (req, res) => {
  let q = 'SELECT * FROM bills WHERE household_id=$1';
  const p = [req.hid];
  if (req.query.recurring === '1') {
    q += ' AND is_recurring=1';
  } else if (req.query.year && req.query.month) {
    p.push(monthPattern(req.query.year, req.query.month));
    q += ` AND due_date LIKE $${p.length}`;
  }
  q += ' ORDER BY due_date ASC';
  res.json((await query(q, p)).map(mapBill));
}));

app.post('/api/bills', auth, wrap(async (req, res) => {
  const { type, description, amount, dueDate, category, isRecurring, memberId } = req.body;
  const id = uid();
  await query(
    'INSERT INTO bills (id,household_id,type,description,amount,due_date,category,is_recurring,member_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
    [id, req.hid, type, description, amount, dueDate, category, isRecurring?1:0, memberId||null]
  );
  res.json({ id });
}));

app.put('/api/bills/:id', auth, wrap(async (req, res) => {
  const { type, description, amount, dueDate, category, status, isRecurring, memberId } = req.body;
  await query(
    'UPDATE bills SET type=$1,description=$2,amount=$3,due_date=$4,category=$5,status=$6,is_recurring=$7,member_id=$8 WHERE id=$9 AND household_id=$10',
    [type, description, amount, dueDate, category, status||'pending', isRecurring?1:0, memberId||null, req.params.id, req.hid]
  );
  res.json({ ok: true });
}));

app.delete('/api/bills/:id', auth, wrap(async (req, res) => {
  await query('DELETE FROM bills WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  res.json({ ok: true });
}));

// Mark bill done → create transaction + next recurrence
app.post('/api/bills/:id/done', auth, wrap(async (req, res) => {
  const bill = await one('SELECT * FROM bills WHERE id=$1 AND household_id=$2', [req.params.id, req.hid]);
  if (!bill) return res.status(404).json({ error: 'Não encontrado' });

  const client = await pool.connect();
  let txId;
  try {
    await client.query('BEGIN');
    await client.query('UPDATE bills SET status=$1 WHERE id=$2', ['done', bill.id]);
    txId = uid();
    await client.query(
      'INSERT INTO transactions (id,household_id,created_by,type,description,amount,category,date,is_recurring,is_fixed,notes,member_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
      [txId, req.hid, req.user.id, bill.type==='bill'?'expense':'income', bill.description, bill.amount, bill.category, bill.due_date, bill.is_recurring, bill.is_recurring, 'Via Agenda', bill.member_id]
    );
    if (bill.is_recurring) {
      const nd = new Date(bill.due_date + 'T12:00:00');
      nd.setMonth(nd.getMonth() + 1);
      const nextDue = nd.toISOString().slice(0,10);
      const existing = await client.query('SELECT id FROM bills WHERE household_id=$1 AND description=$2 AND due_date=$3 AND type=$4', [req.hid, bill.description, nextDue, bill.type]);
      if (!existing.rows.length)
        await client.query(
          'INSERT INTO bills (id,household_id,type,description,amount,due_date,category,is_recurring,member_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
          [uid(), req.hid, bill.type, bill.description, bill.amount, nextDue, bill.category, 1, bill.member_id]
        );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  res.json({ ok: true, txId });
}));

// ─── Start ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n💼 Minhas Finanças rodando em → http://localhost:${PORT}\n`);
    });
  })
  .catch(err => {
    console.error('Falha ao inicializar o banco de dados:', err);
    process.exit(1);
  });
