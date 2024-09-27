import express from "express";
import cors from "cors";
import fetch from "node-fetch"; // Ahora utilizas import en vez de require

const app = express();
app.use(cors());
app.use(express.json());

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

    // Validar que todos los campos requeridos estén presentes
    /*
		if (!publisher_id || !caller_number || !first_name || !last_name || !email) {
        return res.status(400).json({ message: "Missing required fields" });
    }
		*/
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
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

export default app;
