import express from 'express';
import https from 'https';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import cors from 'cors';

// Cargar variables de entorno
dotenv.config();

const app = express();

// Configuración de CORS con las rutas correctas
app.use(cors({
    origin: [
        'https://rpworldllc.com',
        'http://localhost:3001',
        'http://127.0.0.1:3002',
        'https://rpworldllc.com/test/proxy.js',
        'https://rpworldllc.com/test/form.html',
        'https://rpworldllc.com/test/app-test.js'
    ], // Rutas permitidas
    credentials: true // Permitir cookies
}));

app.use(express.json());
app.use(cookieParser());

// Crear conexión a la base de datos SQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

// Middleware para autenticación JWT
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token; // Obtener token de las cookies
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ message: 'Token inválido o expirado' });
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ message: 'No autenticado' });
    }
};

// Ruta para manejar solicitudes al proxy
app.post('/test/api/proxy', authenticateJWT, async (req, res) => {
    const {
        publisher_id,
        caller_number,
        first_name,
        last_name,
        caller_zip,
        caller_state,
        trusted_form_cert_url,
    } = req.body;

    // Validar que todos los campos requeridos estén presentes
    if (!publisher_id || !caller_number || !first_name || !last_name || !caller_zip || !caller_state || !trusted_form_cert_url) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    try {
        const baseURL = 'https://rtb.retreaver.com/rtbs.json';
        const params = new URLSearchParams({
            key: process.env.CAMPAIGN_KEY, // Clave de la campaña desde .env
            publisher_id,
            caller_number,
            first_name,
            last_name,
            caller_zip,
            caller_state,
            trusted_form_cert_url,
        });

        const fullURL = `${baseURL}?${params.toString()}`;
        console.log('Full URL:', fullURL);
        
        // Realizar la solicitud a la API externa
        https.get(fullURL, (resp) => {
            let data = '';

            resp.on('data', (chunk) => {
                data += chunk;
            });

            resp.on('end', async () => {
                try {
                    const parsedData = JSON.parse(data);
                    // Almacenar los datos en la base de datos
                    await pool.query(
                        'INSERT INTO caller_data (publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url]
                    );
                    res.status(200).json({ data: parsedData, fullURL });
                } catch (error) {
                    console.error('Error al parsear la respuesta JSON:', error);
                    res.status(500).json({ message: 'Error al procesar la respuesta', error: error.message });
                }
            });
        }).on('error', (err) => {
            console.error('Error en la solicitud HTTPS:', err);
            res.status(500).json({ message: 'Error interno del servidor', error: err.message });
        });
    } catch (error) {
        console.error('Error interno del servidor:', error);
        res.status(500).json({ message: 'Error interno del servidor', error: error.message });
    }
});

// Iniciar el servidor en el puerto definido
const PORT_PROXY = process.env.PORT_PROXY || 3001; // Usa el puerto 3001 para el proxy
app.listen(PORT_PROXY, () => {
    console.log(`Servidor proxy corriendo en el puerto ${PORT_PROXY}`);
});