import express from 'express';
import https from 'https';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise'; // Importar mysql2
import cors from 'cors';



require('dotenv').config(); // Cargar variables de entorno

// Crear conexión a la base de datos SQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME, // Asegúrate de usar DB_USERNAME aquí
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE, // Asegúrate de usar DB_DATABASE aquí
});


// Definir esquema y modelo de usuario
// (El modelo se reemplaza con consultas SQL, por lo que se elimina el esquema de Mongoose)

// Middleware para autenticación JWT
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token;

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Token inválido o expirado' });
            }
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
            key: process.env.CAMPAIGN_KEY,
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
        console.error('Internal server error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// Ruta para almacenar los datos del formulario
app.post('/test/api/form', async (req, res) => {
    const { publisher_id, caller_number, first_name, last_name, email, caller_state, caller_zip, attorney, incident_date, injured, trusted_form_cert_url } = req.body;

    try {
        const [result] = await pool.query('INSERT INTO form_data (publisher_id, caller_number, first_name, last_name, email, caller_state, caller_zip, attorney, incident_date, injured, trusted_form_cert_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [publisher_id, caller_number, first_name, last_name, email, caller_state, caller_zip, attorney, incident_date, injured, trusted_form_cert_url]);
        res.status(201).json({ message: 'Datos del formulario almacenados correctamente', id: result.insertId });
    } catch (error) {
        console.error('Error al almacenar los datos del formulario:', error);
        res.status(400).json({ message: 'Error al almacenar los datos del formulario', error: error.message });
    }
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
