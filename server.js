const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = 'sua_chave_secreta_aqui'; // Guarda isso em variáveis de ambiente, mas por ora tá assim

// Configuração do banco MySQL - ajusta conforme teu ambiente
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT, // coloca também!
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};


// Cria conexão com banco
async function getConnection() {
  return await mysql.createConnection(dbConfig);
}

// Rota de cadastro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Usuário e senha são obrigatórios!' });
  }
  
  try {
    const conn = await getConnection();

    // Verifica se usuário já existe
    const [rows] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (rows.length > 0) {
      await conn.end();
      return res.status(400).json({ message: 'Usuário já existe!' });
    }
    
    // Cria hash da senha
    const hash = await bcrypt.hash(password, 10);
    
    // Insere usuário no banco
    await conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]);
    await conn.end();
    
    res.json({ message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Usuário e senha são obrigatórios!' });
  }
  
  try {
    const conn = await getConnection();

    // Busca usuário no banco
    const [rows] = await conn.execute('SELECT id, password FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      await conn.end();
      return res.status(400).json({ message: 'Usuário ou senha incorretos!' });
    }
    
    const user = rows[0];
    
    // Compara senha
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      await conn.end();
      return res.status(400).json({ message: 'Usuário ou senha incorretos!' });
    }
    
    // Cria token JWT
    const token = jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '1h' });
    await conn.end();
    
    res.json({ message: 'Login efetuado com sucesso!', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Rota protegida - exemplo de como usar o token
app.get('/profile', async (req, res) => {
  // Pega token do header Authorization: Bearer <token>
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Token não fornecido!' });
  
  try {
    const payload = jwt.verify(token, SECRET);
    
    // Aqui poderia buscar mais dados do usuário no banco
    res.json({ message: 'Dados do perfil', user: payload });
  } catch (error) {
    res.status(403).json({ message: 'Token inválido ou expirado!' });
  }
});

// Inicia o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

