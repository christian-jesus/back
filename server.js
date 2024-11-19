const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Para usar variables de entorno

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Conectar a MongoDB Atlas (usa tu URI)
const uri = process.env.MONGO_URI; // Usando variable de entorno
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch(err => console.error('Error de conexión:', err));

// Definir el esquema de usuario
const usuarioSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Ruta para registrar usuario
app.post('/api/register', async (req, res) => {
  const { username, email, password, age } = req.body;

  if (!email || !password || !username || !age) {
    return res.status(400).json({ mensaje: 'Por favor, complete todos los campos' });
  }

  try {
    // Validar si el email ya existe
    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ mensaje: 'El email ya está registrado' });
    }

    // Hashear la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const nuevoUsuario = new Usuario({ username, email, password: hashedPassword, age });
    await nuevoUsuario.save();

    res.status(201).json({ mensaje: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ mensaje: 'Hubo un error al registrar el usuario' });
  }
});

// Ruta para login de usuario
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ mensaje: 'Por favor, complete todos los campos' });
  }

  try {
    // Buscar usuario por email
    const usuario = await Usuario.findOne({ email });
    if (!usuario) {
      return res.status(400).json({ mensaje: 'Email o contraseña incorrectos' });
    }

    // Verificar que la contraseña coincida
    const esContraseñaCorrecta = await bcrypt.compare(password, usuario.password);
    if (!esContraseñaCorrecta) {
      return res.status(400).json({ mensaje: 'Email o contraseña incorrectos' });
    }

    // Crear un token JWT
    const token = jwt.sign({ userId: usuario._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ mensaje: 'Login exitoso', token });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ mensaje: 'Hubo un error al realizar el login' });
  }
});

// Middleware de autenticación para proteger rutas
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ mensaje: 'Acceso no autorizado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();  // Continuar con la solicitud
  } catch (error) {
    console.error('Error en verificación de token:', error);
    res.status(401).json({ mensaje: 'Token inválido o expirado' });
  }
};

// Ejemplo de una ruta protegida
app.get('/api/protected', verificarToken, (req, res) => {
  res.status(200).json({ mensaje: 'Ruta protegida accesible', user: req.user });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en http://localhost:${PORT}`);
});
