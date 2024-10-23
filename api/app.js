import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import path from 'path';
import https from 'https';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Conectar a MongoDB
mongoose.connect('mongodb+srv://federico:3GTkmnmKh2vii2CK@cluster0.d51o9.mongodb.net/rpsolutions?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error de conexión a MongoDB:', err));

// Esquema de datos de formulario
const formSchema = new mongoose.Schema({
    publisher_id: String,
    caller_number: String,
    first_name: String,
    last_name: String,
    caller_zip: String,
    caller_state: String,
    jornaya_leadid: String,
    trusted_form_cert_url: String,
});

const FormData = mongoose.model('FormData', formSchema);

// Ruta para servir el formulario
app.get('/test/form', (req, res) => {
    res.sendFile(path.join(__dirname, 'public_html', 'form.html'), (err) => {
        if (err) {
            console.error("Error serving form.html:", err.message);
            res.status(500).json({ message: "Error serving form.html", error: err.message });
        }
    });
});

// Ruta para servir proxy.js
app.get('/test/proxy.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public_html', 'proxy.js'), (err) => {
        if (err) {
            console.error("Error serving proxy.js:", err.message);
            res.status(500).json({ message: "Error serving proxy.js", error: err.message });
        }
    });
});

// Ruta para almacenar datos del formulario en MongoDB
app.post('/test/api/forms', async (req, res) => {
    try {
        const formData = new FormData(req.body);
        await formData.save();
        res.status(200).json({ message: 'Form data saved successfully' });
    } catch (error) {
        console.error('Error saving form data:', error.message);
        res.status(500).json({ message: 'Error saving form data', error: error.message });
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

// Iniciar el servidor en el puerto 3001
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});