const scanner = require('./utils/scanner');

(async () => {
    try {
        const tools = ['nmap', 'sqlmap', 'openvas', 'grim'];
        const res = await scanner.runScan('192.168.1.1', tools);
        console.log(JSON.stringify(res, null, 2));
    } catch(e) {
        console.error("ERROR", e);
    }
})();
