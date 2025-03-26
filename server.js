require('dotenv').config({ path: './main.env' });
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

const users = [
  {
    id: 1,
    username: 'admin@example.com',
    password: bcrypt.hashSync('123456', 10),
    role: 'admin',
  },
  {
    id: 2,
    username: 'user@example.com',
    password: bcrypt.hashSync('123456', 10),
    role: 'user',
  },
  {
    id: 3,
    username: 'admin2@example.com',
    password: bcrypt.hashSync('abcdef', 10),
    role: 'admin',
  }
];

const secretKey = process.env.JWT_SECRET;
if (!secretKey) {
  throw new Error("⚠️ ERRO: JWT_SECRET não está definido! Verifique o arquivo .env.");
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Usuário ou senha inválidos' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Usuário ou senha inválidos' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role }, 
    secretKey, 
    { expiresIn: '1h' }
  );
  
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Acesso negado' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Acesso restrito a administradores' });
  }
  next();
};

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Acesso permitido', user: req.user });
});

app.get('/api/admin', authenticateToken, requireAdmin, (req, res) => {
  res.json({ message: 'Bem-vindo à área administrativa', user: req.user });
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
