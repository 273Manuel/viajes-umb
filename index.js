const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path'); // Requerido para trabajar con rutas absolutas

const app = express();
const SECRET_KEY = 'tu_clave_secreta_aqui'; // Cambiar por algo seguro

app.use(cors());
app.use(bodyParser.json());

// Sirve archivos estáticos desde la carpeta 'public' (donde está tu index.html)
app.use(express.static(path.join(__dirname, 'public')));

// Crear base de datos SQLite (archivo viajes.db)
const db = new sqlite3.Database('./viajes.db', (err) => {
  if (err) console.error(err.message);
  else console.log('Base de datos conectada');
});

// Crear tablas si no existen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correo TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS viajes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    origen TEXT NOT NULL,
    destino TEXT NOT NULL,
    fecha TEXT NOT NULL,
    pasajeros INTEGER NOT NULL,
    comentarios TEXT,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  )`);
});

// Middleware para verificar token JWT
function verificarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  const tokenSinBearer = token.replace('Bearer ', '');
  jwt.verify(tokenSinBearer, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token inválido' });
    req.usuarioId = decoded.id;
    next();
  });
}

// Registro de usuario
app.post('/api/register', (req, res) => {
  const { correo, password } = req.body;
  if (!correo || !password) return res.status(400).json({ error: 'Correo y contraseña requeridos' });

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Error en servidor' });

    const sql = `INSERT INTO usuarios (correo, password) VALUES (?, ?)`;
    db.run(sql, [correo.toLowerCase(), hash], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ error: 'Correo ya registrado' });
        }
        return res.status(500).json({ error: 'Error en base de datos' });
      }
      res.json({ message: 'Usuario registrado' });
    });
  });
});

// Login usuario
app.post('/api/login', (req, res) => {
  const { correo, password } = req.body;
  if (!correo || !password) return res.status(400).json({ error: 'Correo y contraseña requeridos' });

  const sql = `SELECT * FROM usuarios WHERE correo = ?`;
  db.get(sql, [correo.toLowerCase()], (err, row) => {
    if (err) return res.status(500).json({ error: 'Error en base de datos' });
    if (!row) return res.status(401).json({ error: 'Usuario no encontrado' });

    bcrypt.compare(password, row.password, (err, igual) => {
      if (err) return res.status(500).json({ error: 'Error en servidor' });
      if (!igual) return res.status(401).json({ error: 'Contraseña incorrecta' });

      // Generar token JWT (expira en 1 día)
      const token = jwt.sign({ id: row.id, correo: row.correo }, SECRET_KEY, { expiresIn: '1d' });
      res.json({ token });
    });
  });
});

// Publicar viaje (requiere token)
app.post('/api/viajes', verificarToken, (req, res) => {
  const { origen, destino, fecha, pasajeros, comentarios } = req.body;
  if (!origen || !destino || !fecha || !pasajeros) {
    return res.status(400).json({ error: 'Faltan datos obligatorios' });
  }

  const sql = `INSERT INTO viajes (usuario_id, origen, destino, fecha, pasajeros, comentarios) VALUES (?, ?, ?, ?, ?, ?)`;
  db.run(sql, [req.usuarioId, origen, destino, fecha, pasajeros, comentarios || null], function(err) {
    if (err) return res.status(500).json({ error: 'Error al guardar viaje' });
    res.json({ message: 'Viaje publicado', id: this.lastID });
  });
});

// Obtener viajes con info usuario
app.get('/api/viajes', (req, res) => {
  const sql = `
    SELECT v.id, v.origen, v.destino, v.fecha, v.pasajeros, v.comentarios, u.correo as usuario
    FROM viajes v JOIN usuarios u ON v.usuario_id = u.id
    ORDER BY v.fecha ASC
  `;
  db.all(sql, [], (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error al obtener viajes' });
    res.json(filas);
  });
});

// Puerto y arrancar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en puerto ${PORT}`);
});

// Configuración adicional para producción
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo salió mal' });
});
