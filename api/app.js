import express from 'express';
import https from 'https';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import cors from 'cors';
import path from 'path';

// Cargar variables de entorno
dotenv.config();

const app = express();

// Configuraci車n de CORS con rutas adicionales
app.use(cors({
    origin: [
        'https://rpworldllc.com',
        'http://localhost:3001',
        'http://127.0.0.1:3002',
        'https://rpworldllc.com/test/proxy.js',
        'https://rpworldllc.com/test/form.html',
        'https://rpworldllc.com/test/app-test.js'
    ],
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// Crear conexi車n a la base de datos SQL como un "pool"
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

// Middleware de autenticaci車n JWT
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Acceso no autorizado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inv芍lido' });

        req.user = user;
        next();
    });
};

// Ruta para recibir datos del formulario principal
app.post('/api/form', authenticateJWT, async (req, res) => {
    const {
        publisher_id,
        caller_number,
        first_name,
        last_name,
        caller_zip,
        caller_state,
        trusted_form_cert_url
    } = req.body;

    // Validaci車n de los datos recibidos
    if (!publisher_id || !caller_number || !first_name || !last_name || !caller_zip || !caller_state || !trusted_form_cert_url) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    // Inserci車n en la base de datos
    const query = `
       INSERT INTO rpworldllc_form_submissions (publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    try {
        const [result] = await pool.query(query, [publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url]);
        res.status(200).json({ message: 'Datos guardados exitosamente', data: result });
    } catch (err) {
        console.error('Error al insertar en la base de datos:', err);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Ruta de autenticaci車n para generar JWT
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.TEST_USERNAME && password === process.env.TEST_PASSWORD) {
        const user = { username };
        const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Credenciales incorrectas' });
    }
});

// Rutas adicionales para servir los archivos nuevos
app.use('/test/proxy.js', express.static(path.join('/home/rpworldllc/public_html/test/proxy.js')));
app.use('/test/form.html', express.static(path.join('/home/rpworldllc/public_html/test/form.html')));
app.use('/test/app-test.js', express.static(path.join('/home/rpworldllc/public_html/test/app-test.js')));

// Nueva ruta POST para el formulario en test/form.html
app.post('/test/form', authenticateJWT, async (req, res) => {
    const { testField1, testField2 } = req.body;
    
    if (!testField1 || !testField2) {
        return res.status(400).json({ message: 'Todos los campos de test son obligatorios' });
    }

    res.status(200).json({ message: 'Datos de test recibidos exitosamente' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
