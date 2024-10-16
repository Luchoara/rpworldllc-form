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
    refreshToken: { type: String } // Agregar campo para almacenar el refreshToken
});

const User = mongoose.model('User', userSchema);

// Definir esquema y modelo para los datos del formulario
const formSchema = new mongoose.Schema({
    key: String,
    publisher_id: String,
    caller_number: String,
    first_name: String,
    last_name: String,
    email: String,
    caller_state: String,
    caller_zip: String,
    attorney: String,
    incident_date: String,
    injured: String,
    trusted_form_cert_url: String,
});

const Form = mongoose.model('Form', formSchema);

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
    const user = await User.findOne({ username });

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
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000, // 15 minutos
            });

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
            });

            // Guardar el refresh token en la base de datos
            user.refreshToken = refreshToken;
            await user.save();

            res.status(200).json({ message: 'Autenticado correctamente' });
        } else {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
    } else {
        return res.status(401).json({ message: 'Usuario no encontrado' });
    }
});

// Ruta para obtener un nuevo token
app.post('/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No hay refresh token' });
    }

    try {
        // Verificar si el refresh token es válido
        const user = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Buscar el usuario en la base de datos
        const foundUser = await User.findOne({ username: user.id });

        if (!foundUser || foundUser.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Refresh token inválido' });
        }

        // Generar un nuevo JWT (access token)
        const newAccessToken = jwt.sign({ id: foundUser.username }, process.env.JWT_SECRET, {
            expiresIn: '15m',
        });

        // Generar un nuevo refresh token
        const newRefreshToken = jwt.sign({ id: foundUser.username }, process.env.JWT_REFRESH_SECRET, {
            expiresIn: '7d',
        });

        // Actualizar el refreshToken del usuario en la base de datos
        foundUser.refreshToken = newRefreshToken;
        await foundUser.save();

        // Renovar el token en las cookies
        res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000, // 15 minutos
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
        });

        res.status(200).json({ message: 'Token renovado' });
    } catch (err) {
        console.error('Error al renovar el token:', err); // Log de error
        return res.status(403).json({ message: 'Refresh token inválido o expirado' });
    }
});

// Ruta para obtener todos los usuarios registrados
app.get('/users', authenticateJWT, async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 }); // Excluye la contraseña
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    }
});

// Ruta para manejar solicitudes al proxy
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
app.post('/api/forms', async (req, res) => {
    const {
        key,
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

    const formData = new Form({
        key,
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

    try {
        await formData.save();
        res.status(201).json({ message: 'Datos del formulario guardados correctamente' });
    } catch (error) {
        res.status(400).json({ message: 'Error al guardar los datos del formulario', error: error.message });
    }
});

// Ruta para logout
app.post('/logout', authenticateJWT, async (req, res) => {
    const user = await User.findOne({ username: req.user.id });
    if (user) {
        // Limpiar el refreshToken del usuario
        user.refreshToken = null;
        await user.save();

        res.clearCookie('token');
        res.clearCookie('refreshToken');
        res.status(200).json({ message: 'Logout exitoso' });
    } else {
        res.status(404).json({ message: 'Usuario no encontrado' });
    }
});

// Iniciar el servidor
app.listen(process.env.PORT || 3000, () => {
    console.log(`Servidor corriendo en el puerto ${process.env.PORT || 3000}`);
});
