const express = require('express');
const router = express.Router();
const axios = require('axios');

// IP Intelligence Lookup
router.get('/:ip', async (req, res) => {
    try {
        const ip = req.params.ip;
        
        // Using ipapi.co (reliable alternative)
        const response = await axios.get(`https://ipapi.co/${ip}/json/`);
        
        if (response.data.error) {
            return res.status(400).json({ error: response.data.reason || 'Invalid IP address' });
        }

        // Map ipapi.co data to our expected format
        const d = response.data;
        const mappedData = {
            query: d.ip,
            city: d.city,
            regionName: d.region,
            country: d.country_name,
            isp: d.org,
            org: d.org,
            as: d.asn,
            lat: d.latitude,
            lon: d.longitude,
            timezone: d.timezone
        };

        res.json({
            success: true,
            data: mappedData
        });

    } catch (error) {
        console.error('IP Info Error:', error);
        res.status(500).json({ error: 'Failed to fetch IP information' });
    }
});

module.exports = router;
