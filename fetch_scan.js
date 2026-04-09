const http = require('http');
const data = JSON.stringify({
  target: '192.168.1.1',
  tools: ['sqlmap'],
  profile: 'standard',
  options: {}
});

const options = {
  hostname: '127.0.0.1',
  port: 3000,
  path: '/api/scan/start',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
};

const req = http.request(options, res => {
  let r = '';
  res.on('data', c => r += c);
  res.on('end', () => console.log("Response:", r));
});
req.on('error', e => console.error("Error:", e));
req.write(data);
req.end();
