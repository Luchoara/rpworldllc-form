import express from 'express';
import https from 'https';

const app = express();

// Middleware para parsear JSON
app.use(express.json());

app.post("api/proxy", async (req, res) => {
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
        console.log("esto es el /api/proxy.js");
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
                    res.status(500).json({ message: "Error parsing JSON response", error: error.message });
                }
            });

        }).on("error", (err) => {
            console.error("Error: " + err.message);
            console.log("api/proxy.js");
            res.status(500).json({ message: "Internal server error", error: err.message });
        });

    } catch (error) {
        console.error("Internal server error:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

// Inicia el servidor en el puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

