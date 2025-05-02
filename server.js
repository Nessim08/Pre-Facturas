// server.js

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// Usar el puerto proporcionado por Render, o 5000 como fallback
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Configuración para el almacenamiento de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Crear directorio de uploads si no existe
const fs = require('fs');
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// MongoDB Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['provider', 'admin'], default: 'provider' }
});

const invoiceSchema = new mongoose.Schema({
  provider: { type: String, required: true },
  date: { type: Date, default: Date.now },
  amount: { type: Number, required: true },
  status: { type: String, default: 'Pending' },
  filename: { type: String, required: true },
  filepath: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);
const Invoice = mongoose.model('Invoice', invoiceSchema);

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Authentication required' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Ruta para la raíz del sitio (home)
app.get('/', (req, res) => {
  res.send('Bienvenido a la API de Pre-Facturas!');
});

// Rutas de la API
app.post('/api/users/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      password: hashedPassword,
      role
    });
    
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Subir factura
app.post('/api/invoices/upload', authenticateToken, upload.single('invoice'), async (req, res) => {
  try {
    const { provider, amount } = req.body;
    
    const invoice = new Invoice({
      provider,
      amount,
      filename: req.file.filename,
      filepath: req.file.path
    });
    
    await invoice.save();
    res.status(201).json({ message: 'Invoice uploaded successfully', invoice });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch((error) => console.log('Error connecting to MongoDB: ', error));

// Escuchar en el puerto
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



