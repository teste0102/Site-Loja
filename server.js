require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// Pastas
const PUBLIC_DIR = path.join(__dirname, 'public');
const IMAGES_DIR = path.join(PUBLIC_DIR, 'imagens');

// >>> Diretório gravável no Azure
const DATA_DIR =
  process.env.DATA_DIR || path.join(process.env.HOME || '/home', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
}

// Helpers
function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
      return [];
    }
    const raw = fs.readFileSync(USERS_FILE, 'utf-8');
    if (!raw || !raw.trim()) {
      writeUsers([]);
      return [];
    }
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.users)) return [];
    return parsed.users;
  } catch (e) {
    console.error('Falha ao ler users.json:', e);
    writeUsers([]);
    return [];
  }
}

function writeUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2));
  } catch (e) {
    console.error('Erro ao salvar users.json:', e);
  }
}

// Seed do admin
(function ensureAdmin() {
  const users = readUsers();
  const adminUser = process.env.ADMIN_USER || 'sikavial';
  const adminPass = process.env.ADMIN_PASS || '123456789A@';
  const exists = users.find(u => u.username.toLowerCase() === adminUser.toLowerCase());
  if (!exists) {
    const hash = bcrypt.hashSync(adminPass, 10);
    users.push({
      id: Date.now().toString(),
      username: adminUser,
      password: hash,
      role: 'admin',
      createdAt: new Date().toISOString()
    });
    writeUsers(users);
    console.log('> Conta admin criada:', adminUser);
  }
})();

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// Auth helpers
function setAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false // mude para true se usar HTTPS com domínio
  });
}
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// Rotas de autenticação
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Senha deve ter pelo menos 8 caracteres.' });
  }

  const users = readUsers();
  const exists = users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (exists) return res.status(409).json({ error: 'Usuário já existe.' });

  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now().toString(),
    username,
    password: hash,
    role: 'user',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeUsers(users);
  setAuthCookie(res, { id: user.id, username: user.username, role: user.role });
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const users = readUsers();
  const user = users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  setAuthCookie(res, { id: user.id, username: user.username, role: user.role });
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ user: null });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ user: { id: payload.id, username: payload.username, role: payload.role } });
  } catch (e) {
    return res.json({ user: null });
  }
});

// Listar imagens ordenadas pelo número final
app.get('/api/images', (req, res) => {
  if (!fs.existsSync(IMAGES_DIR)) return res.json({ images: [] });
  const files = fs.readdirSync(IMAGES_DIR)
    .filter(f => /\.(jpg|jpeg|png|webp|gif)$/i.test(f));

  const parsed = files.map(name => {
    const noExt = name.replace(/\.[^.]+$/, '');
    const m = noExt.match(/(.*)\s(\d+)$/); // pega número no final
    const order = m ? parseInt(m[2], 10) : Number.MAX_SAFE_INTEGER;
    const label = m ? m[1] : noExt;
    return { name, url: `/imagens/${name}`, order, label };
  });

  parsed.sort((a, b) => a.order - b.order);
  res.json({ images: parsed });
});

// Start
app.listen(PORT, '0.0.0.0', () => console.log(`> Servidor em http://localhost:${PORT}`));
