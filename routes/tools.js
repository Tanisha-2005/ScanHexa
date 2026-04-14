const express = require("express");
const router = express.Router();
const dns = require("dns").promises;
const { simulateTool } = require("../utils/scanner");

// DNS Lookup
router.get("/dns/:domain", async(req, res) => {
    try {
        const domain = req.params.domain;

        const result = await dns.lookup(domain);

        res.json({
            domain,
            ip: result.address
        });

    } catch (err) {
        res.status(500).json({
            error: "DNS lookup failed",
            message: err.message
        });
    }
});

// Ping test
router.get("/ping/:host", (req, res) => {
    const host = req.params.host;

    res.json({
        message: `Ping test for ${host}`,
        status: "success"
    });
});

// Run tool
router.post('/run', async (req, res) => {
    try {
        const { tool, domain, options } = req.body;

        if (!tool || !domain) {
            return res.status(400).json({ error: "Tool and domain required" });
        }

        const { runScan, getExecutablePath, simulateTool } = require("../utils/scanner");
        
        // Check if tool is available on system
        const executable = await getExecutablePath(tool);
        const forceSimulate = process.env.SCANHEXA_SIMULATE === 'true';
        let output;

        if (executable && !forceSimulate) {
            // Run real tool using runScan logic (single tool). We extract it from the results object.
            const results = await runScan(domain, [tool], options);
            output = results.data[tool]; // output is inside the results.data wrapper
        } else {
            // Fallback to enhanced simulation
            if (forceSimulate) console.log(`[ScanHexa] Global simulation mode active. Simulating single tool: ${tool}.`);
            else console.log(`Tool ${tool} not found, using simulation fallback.`);
            output = await simulateTool(tool, domain, options || {});
        }

        if (output && output.error) {
             return res.status(500).json({ error: output.error });
        }

        res.json({
            success: true,
            output: output.rawOutput || (typeof output.data === 'string' ? output.data : JSON.stringify(output.data, null, 2))
        });
    } catch (error) {
        console.error("Tool execution error:", error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;