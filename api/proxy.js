import express from "express";
import cors from "cors";
import fetch from "node-fetch"; // Ahora utilizas import en vez de require
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());

// Sirve archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

app.post("/api/proxy", async (req, res) => {
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
        const baseURL = "https://rtb.retreaver.com/rtbs.json";
        const params = new URLSearchParams({
            key: "136b19e3-3912-476a-8b5b-9a8de3fee354", // Campaign 818 MVA 1 - Pub 128
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
        console.log("Full URL:", fullURL);

        const response = await fetch(fullURL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
        });

        if (response.ok) {
            const data = await response.json();
            res.status(200).json({ data, fullURL });
        } else {
            res.status(response.status).json({ message: "Error in API response" });
        }
    } catch (error) {
        console.error("Internal server error:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

// Ruta para servir el index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'form.html'));
});

// abort controller 
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 segundos

try {
    const response = await fetch(fullURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal, // Para manejar el timeout
    });
    clearTimeout(timeoutId);
} catch (error) {
    if (error.name === 'AbortError') {
        res.status(408).json({ message: "Request timed out" });
    } else {
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
}


// Escuchar en el puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

export default app;
