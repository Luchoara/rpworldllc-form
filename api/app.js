import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config(); // Cargar variables de entorno

const app = express();
app.use(cors({
    origin: [
        'http://localhost:3001', // Permitir localhost en modo desarrollo
        'https://rpworldllc.com'  // Permitir el dominio en producción
    ],
    credentials: true // Permitir cookies
}));
app.use(express.json());

// Crear conexión a la base de datos SQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

// Ruta para probar la conexión a la base de datos
app.get('/test/db-connection', async (req, res) => {
    try {
        await pool.query('SELECT 1'); // Consulta simple para probar la conexión
        res.status(200).json({ message: "Conexión a la base de datos exitosa" });
    } catch (error) {
        console.error('Error de conexión:', error.message);
        res.status(500).json({ message: "Error de conexión a la base de datos", error: error.message });
    }
});

// Ruta de prueba simple
app.get('/test/ping', (req, res) => {
    res.status(200).send('Pong');
});

// Ruta para servir el formulario
app.get('/test/form', (req, res) => {
    res.sendFile(path.join(__dirname, 'public_html', 'form.html'), (err) => {
        if (err) {
            console.error("Error serving form.html:", err.message);
            res.status(500).json({ message: "Error serving form.html", error: err.message });
        }
    });
});

// Ruta para almacenar datos del formulario en SQL
app.post('/test/api/forms', async (req, res) => {
    const { publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url } = req.body;

    try {
        const [result] = await pool.query('INSERT INTO form_data (publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url) VALUES (?, ?, ?, ?, ?, ?, ?)', [publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url]);
        res.status(200).json({ message: 'Datos del formulario almacenados correctamente', id: result.insertId });
    } catch (error) {
        console.error('Error al almacenar los datos del formulario:', error.message);
        res.status(500).json({ message: 'Error al almacenar los datos del formulario', error: error.message });
    }
});

// Iniciar el servidor en el puerto 3002
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
