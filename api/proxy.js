import express from 'express';
import https from 'https';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

// Cargar variables de entorno
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// Conectar a la base de datos MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error de conexión a MongoDB:', err));

// Definir esquema y modelo de usuario
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Middleware para autenticación JWT
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token; // Leer token de la cookie

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Token inválido o expirado' });
            }
            req.user = user; // Agrega el usuario al request
            next();
        });
    } else {
        res.status(401).json({ message: 'No autenticado' });
    }
};

// Ruta para registro de usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Cifrado de contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guarda el usuario con la contraseña cifrada
    const newUser = new User({ username, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).json({ message: 'Usuario registrado' });
    } catch (error) {
        res.status(400).json({ message: 'Error al registrar el usuario', error: error.message });
    }
});

// Ruta para login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Busca al usuario en la base de datos
    const user = await User.findOne({ username }); // Busca en MongoDB

    if (user) {
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            const jwtToken = jwt.sign({ id: user.username }, process.env.JWT_SECRET, {
                expiresIn: '15m', // Token expira en 15 minutos
            });

            const refreshToken = jwt.sign({ id: user.username }, process.env.JWT_REFRESH_SECRET, {
                expiresIn: '7d', // Refresh token expira en 7 días
            });

            // Guardar tokens en cookies seguras
            res.cookie('token', jwtToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000, // 15 minutos
            });

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
            });

            res.status(200).json({ message: 'Autenticado correctamente' });
        } else {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
    } else {
        return res.status(401).json({ message: 'Usuario no encontrado' });
    }
});

// Ruta para obtener un nuevo token
app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Refresh token inválido o expirado' });
            }

            // Generar un nuevo JWT
            const newToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
                expiresIn: '15m',
            });

            res.cookie('token', newToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000, // 15 minutos
            });

            res.status(200).json({ message: 'Token renovado' });
        });
    } else {
        res.status(401).json({ message: 'No hay refresh token' });
    }
});

// Ruta para manejar las solicitudes al proxy
app.post('/api/proxy', authenticateJWT, async (req, res) => {
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
            key: '136b19e3-3912-476a-8b5b-9a8de3fee354', // Campaign 818 MVA 1 - Pub 128
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

            // Recibe datos en chunks
            resp.on('data', (chunk) => {
                data += chunk;
            });

            // Cuando se recibe toda la respuesta
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

// Inicia el servidor en el puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
