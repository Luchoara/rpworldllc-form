require('dotenv').config(); // Cargar variables de entorno

const express = require('express'); // Importar express
const mysql = require('mysql2/promise'); // Importar mysql
const cors = require('cors'); // Importar cors
const path = require('path'); // Importar path
const https = require('https'); // Importar https

const app = express(); // Definir la aplicación express
const corsOptions = {
    origin: 'http://127.0.0.1:5500', // Permitir solicitudes desde este origen
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'], // Permitir estas cabeceras
};

app.use(cors(corsOptions)); // Usar CORS
app.use(express.json()); // Usar JSON en las solicitudes

// Crear conexión a la base de datos SQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

// Agrega un mensaje para verificar la conexión
pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
    } else {
        console.log('Conexión exitosa a la base de datos');
        connection.release(); // Libera la conexión
    }
});

// Ruta para servir el formulario
app.get('/test/form', (req, res) => {
    res.sendFile(path.join(__dirname, 'public_html', 'form.html'), (err) => {
        if (err) {
            console.error("Error sirviendo form.html:", err.message);
            res.status(500).json({ message: "Error sirviendo form.html", error: err.message });
        }
    });
});

// Manejar solicitudes OPTIONS
app.options('/test/api/form', cors(corsOptions)); // Permitir solicitudes OPTIONS

// Ruta para almacenar datos del formulario en SQL
app.post('/test/api/form', async (req, res) => {
    const { publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, jornaya_leadid, trusted_form_cert_url } = req.body;

    try {
        const [result] = await pool.query('INSERT INTO form_data (publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, jornaya_leadid, trusted_form_cert_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, jornaya_leadid, trusted_form_cert_url]);
        res.status(200).json({ message: 'Datos del formulario almacenados correctamente', id: result.insertId });
    } catch (error) {
        console.error('Error al almacenar los datos del formulario:', error.message);
        res.status(500).json({ message: 'Error al almacenar los datos del formulario', error: error.message });
    }
});

// Ruta para el proxy que envía datos a la API externa
app.post('/test/api/proxy', async (req, res) => {
    const {
        publisher_id,
        caller_number,
        first_name,
        last_name,
        email,
        caller_state,
        caller_zip,
        attorney,
        incident_date,
        injured,
        trusted_form_cert_url,
    } = req.body;

    try {
        const baseURL = 'https://rtb.retreaver.com/rtbs.json';
        const params = new URLSearchParams({
            key: '136b19e3-3912-476a-8b5b-9a8de3fee354',
            publisher_id,
            caller_number,
            first_name,
            last_name,
            email,
            caller_state,
            caller_zip,
            attorney,
            incident_date,
            injured,
            trusted_form_cert_url,
        });

        const fullURL = `${baseURL}?${params.toString()}`;
        console.log('Full URL:', fullURL);

        https.get(fullURL, (resp) => {
            let data = '';

            resp.on('data', (chunk) => {
                data += chunk;
            });

            resp.on('end', () => {
                try {
                    const parsedData = JSON.parse(data);
                    res.status(200).json({ data: parsedData, fullURL });
                } catch (error) {
                    res.status(500).json({ message: 'Error parsing JSON response', error: error.message });
                }
            });
        }).on('error', (err) => {
            console.error('Error: ' + err.message);
            res.status(500).json({ message: 'Internal server error', error: err.message });
        });
    } catch (error) {
        console.error('Internal server error:', error.message);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// Iniciar el servidor en el puerto 3002
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
