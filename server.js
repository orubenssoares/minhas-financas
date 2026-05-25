const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Database ───────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'financas.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS households (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    household_id TEXT NOT NULL REFERENCES households(id),
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    color TEXT DEFAULT '#3b82f6',
    created_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ─── Helpers ────────────────────────────────────────────────
const uid = () => crypto.randomUUID();
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

// ─── Auth middleware ─────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > datetime("now")').get(token);
  if (!session) return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
  req.user = user;
  req.hid  = user.household_id;
  next();
}

// ─── AUTH ────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, householdName, inviteCode } = req.body;
    if (!name?.trim() || !email?.trim() || !password)
      return res.status(400).json({ error: 'Preencha todos os campos obrigatórios' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase()))
      return res.status(400).json({ error: 'E-mail já cadastrado' });

    let householdId;
    if (inviteCode?.trim()) {
      const hh = db.prepare('SELECT * FROM households WHERE invite_code = ?').get(inviteCode.trim().toUpperCase());
      if (!hh) return res.status(400).json({ error: 'Código de convite inválido' });
      householdId = hh.id;
    } else {
      if (!householdName?.trim()) return res.status(400).json({ error: 'Nome da casa é obrigatório' });
      householdId = uid();
      const invite = crypto.randomBytes(3).toString('hex').toUpperCase();
      db.prepare('INSERT INTO households (id, name, invite_code) VALUES (?, ?, ?)').run(householdId, householdName.trim(), invite);
      DEFAULT_CATS.forEach(c =>
        db.prepare('INSERT INTO categories (id, household_id, name, monthly_limit, color) VALUES (?, ?, ?, ?, ?)').run(uid(), householdId, c.name, c.limit, c.color)
      );
    }

    const count = db.prepare('SELECT count(*) as c FROM members WHERE household_id = ?').get(householdId).c;
    const color = MEMBER_COLORS[count % MEMBER_COLORS.length];
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uid();

    db.prepare('INSERT INTO users (id, household_id, name, email, password_hash, color) VALUES (?, ?, ?, ?, ?, ?)').run(userId, householdId, name.trim(), email.toLowerCase(), passwordHash, color);
    db.prepare('INSERT INTO members (id, household_id, name, color, user_id) VALUES (?, ?, ?, ?, ?)').run(uid(), householdId, name.trim(), color, userId);

    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, new Date(Date.now() + 30*86400*1000).toISOString());

    const hh = db.prepare('SELECT * FROM households WHERE id = ?').get(householdId);
    res.json({ token, user: { id: userId, name: name.trim(), email: email.toLowerCase(), color, householdId, householdName: hh.name, inviteCode: hh.invite_code } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email?.toLowerCase());
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(400).json({ error: 'E-mail ou senha incorretos' });

    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, new Date(Date.now() + 30*86400*1000).toISOString());
    const hh = db.prepare('SELECT * FROM households WHERE id = ?').get(user.household_id);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, color: user.color, householdId: user.household_id, householdName: hh?.name, inviteCode: hh?.invite_code } });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

app.post('/api/auth/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.headers.authorization?.replace('Bearer ', ''));
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  const hh = db.prepare('SELECT * FROM households WHERE id = ?').get(req.hid);
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email, color: req.user.color, householdId: req.hid, householdName: hh?.name, inviteCode: hh?.invite_code });
});

// ─── MEMBERS ─────────────────────────────────────────────────
app.get('/api/members', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM members WHERE household_id = ?').all(req.hid))
);

app.post('/api/members', auth, (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nome obrigatório' });
  const id = uid();
  db.prepare('INSERT INTO members (id, household_id, name, color) VALUES (?, ?, ?, ?)').run(id, req.hid, name.trim(), color || '#3b82f6');
  res.json({ id, name: name.trim(), color: color || '#3b82f6', household_id: req.hid });
});

app.put('/api/members/:id', auth, (req, res) => {
  const { name, color } = req.body;
  db.prepare('UPDATE members SET name=?, color=? WHERE id=? AND household_id=?').run(name?.trim(), color, req.params.id, req.hid);
  res.json({ ok: true });
});

app.delete('/api/members/:id', auth, (req, res) => {
  db.prepare('UPDATE transactions SET member_id=NULL WHERE member_id=?').run(req.params.id);
  db.prepare('UPDATE bills SET member_id=NULL WHERE member_id=?').run(req.params.id);
  db.prepare('DELETE FROM members WHERE id=? AND household_id=?').run(req.params.id, req.hid);
  res.json({ ok: true });
});

// ─── TRANSACTIONS ─────────────────────────────────────────────
app.get('/api/transactions', auth, (req, res) => {
  let q = 'SELECT * FROM transactions WHERE household_id = ?';
  const p = [req.hid];
  if (req.query.year && req.query.month) {
    q += ` AND strftime('%Y',date)=? AND strftime('%m',date)=?`;
    p.push(req.query.year.toString(), req.query.month.toString().padStart(2,'0'));
  }
  q += ' ORDER BY date DESC, created_at DESC';
  res.json(db.prepare(q).all(...p).map(mapTx));
});

app.post('/api/transactions', auth, (req, res) => {
  const { type, description, amount, category, date, isRecurring, isFixed, notes, memberId } = req.body;
  const id = uid();
  db.prepare('INSERT INTO transactions (id,household_id,created_by,type,description,amount,category,date,is_recurring,is_fixed,notes,member_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(id, req.hid, req.user.id, type, description, amount, category, date, isRecurring?1:0, isFixed?1:0, notes||'', memberId||null);
  res.json({ id });
});

app.put('/api/transactions/:id', auth, (req, res) => {
  const { type, description, amount, category, date, isRecurring, isFixed, notes, memberId } = req.body;
  db.prepare('UPDATE transactions SET type=?,description=?,amount=?,category=?,date=?,is_recurring=?,is_fixed=?,notes=?,member_id=? WHERE id=? AND household_id=?')
    .run(type, description, amount, category, date, isRecurring?1:0, isFixed?1:0, notes||'', memberId||null, req.params.id, req.hid);
  res.json({ ok: true });
});

app.delete('/api/transactions/:id', auth, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id=? AND household_id=?').run(req.params.id, req.hid);
  res.json({ ok: true });
});

// ─── CATEGORIES ──────────────────────────────────────────────
app.get('/api/categories', auth, (req, res) =>
  res.json(db.prepare('SELECT id, name, monthly_limit as "limit", color FROM categories WHERE household_id=?').all(req.hid))
);

app.post('/api/categories', auth, (req, res) => {
  const { name, limit, color } = req.body;
  const id = uid();
  db.prepare('INSERT INTO categories (id,household_id,name,monthly_limit,color) VALUES (?,?,?,?,?)').run(id, req.hid, name, limit||0, color||'#6b7280');
  res.json({ id });
});

app.put('/api/categories/:id', auth, (req, res) => {
  const { name, limit, color } = req.body;
  db.prepare('UPDATE categories SET name=?,monthly_limit=?,color=? WHERE id=? AND household_id=?').run(name, limit||0, color, req.params.id, req.hid);
  res.json({ ok: true });
});

app.delete('/api/categories/:id', auth, (req, res) => {
  db.prepare('DELETE FROM categories WHERE id=? AND household_id=?').run(req.params.id, req.hid);
  res.json({ ok: true });
});

// ─── GOALS ───────────────────────────────────────────────────
app.get('/api/goals', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM goals WHERE household_id=?').all(req.hid).map(mapGoal))
);

app.post('/api/goals', auth, (req, res) => {
  const { name, targetAmount, currentAmount, deadline, color } = req.body;
  const id = uid();
  db.prepare('INSERT INTO goals (id,household_id,name,target_amount,current_amount,deadline,color) VALUES (?,?,?,?,?,?,?)').run(id, req.hid, name, targetAmount, currentAmount||0, deadline||null, color||'#3b82f6');
  res.json({ id });
});

app.put('/api/goals/:id', auth, (req, res) => {
  const { name, targetAmount, currentAmount, deadline, color } = req.body;
  db.prepare('UPDATE goals SET name=?,target_amount=?,current_amount=?,deadline=?,color=? WHERE id=? AND household_id=?').run(name, targetAmount, currentAmount||0, deadline||null, color, req.params.id, req.hid);
  res.json({ ok: true });
});

app.delete('/api/goals/:id', auth, (req, res) => {
  db.prepare('DELETE FROM goals WHERE id=? AND household_id=?').run(req.params.id, req.hid);
  res.json({ ok: true });
});

// ─── BILLS ───────────────────────────────────────────────────
app.get('/api/bills', auth, (req, res) => {
  let q = 'SELECT * FROM bills WHERE household_id=?';
  const p = [req.hid];
  if (req.query.year && req.query.month) {
    q += ` AND strftime('%Y',due_date)=? AND strftime('%m',due_date)=?`;
    p.push(req.query.year.toString(), req.query.month.toString().padStart(2,'0'));
  }
  res.json(db.prepare(q).all(...p).map(mapBill));
});

app.post('/api/bills', auth, (req, res) => {
  const { type, description, amount, dueDate, category, isRecurring, memberId } = req.body;
  const id = uid();
  db.prepare('INSERT INTO bills (id,household_id,type,description,amount,due_date,category,is_recurring,member_id) VALUES (?,?,?,?,?,?,?,?,?)').run(id, req.hid, type, description, amount, dueDate, category, isRecurring?1:0, memberId||null);
  res.json({ id });
});

app.put('/api/bills/:id', auth, (req, res) => {
  const { type, description, amount, dueDate, category, status, isRecurring, memberId } = req.body;
  db.prepare('UPDATE bills SET type=?,description=?,amount=?,due_date=?,category=?,status=?,is_recurring=?,member_id=? WHERE id=? AND household_id=?')
    .run(type, description, amount, dueDate, category, status||'pending', isRecurring?1:0, memberId||null, req.params.id, req.hid);
  res.json({ ok: true });
});

app.delete('/api/bills/:id', auth, (req, res) => {
  db.prepare('DELETE FROM bills WHERE id=? AND household_id=?').run(req.params.id, req.hid);
  res.json({ ok: true });
});

// Mark bill done → create transaction + next recurrence
app.post('/api/bills/:id/done', auth, (req, res) => {
  const bill = db.prepare('SELECT * FROM bills WHERE id=? AND household_id=?').get(req.params.id, req.hid);
  if (!bill) return res.status(404).json({ error: 'Não encontrado' });

  const doIt = db.transaction(() => {
    db.prepare('UPDATE bills SET status=? WHERE id=?').run('done', bill.id);
    const txId = uid();
    db.prepare('INSERT INTO transactions (id,household_id,created_by,type,description,amount,category,date,is_recurring,is_fixed,notes,member_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(txId, req.hid, req.user.id, bill.type==='bill'?'expense':'income', bill.description, bill.amount, bill.category, bill.due_date, bill.is_recurring, bill.is_recurring, 'Via Agenda', bill.member_id);
    if (bill.is_recurring) {
      const nd = new Date(bill.due_date + 'T12:00:00');
      nd.setMonth(nd.getMonth() + 1);
      const nextDue = nd.toISOString().slice(0,10);
      const exists = db.prepare('SELECT id FROM bills WHERE household_id=? AND description=? AND due_date=? AND type=?').get(req.hid, bill.description, nextDue, bill.type);
      if (!exists)
        db.prepare('INSERT INTO bills (id,household_id,type,description,amount,due_date,category,is_recurring,member_id) VALUES (?,?,?,?,?,?,?,?,?)').run(uid(), req.hid, bill.type, bill.description, bill.amount, nextDue, bill.category, 1, bill.member_id);
    }
    return txId;
  });
  res.json({ ok: true, txId: doIt() });
});

// ─── Start ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n💼 Minhas Finanças rodando em → http://localhost:${PORT}\n`);
  console.log('   Pressione Ctrl+C para parar\n');
});
