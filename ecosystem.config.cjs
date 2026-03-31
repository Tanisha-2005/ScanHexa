module.exports = {
    apps: [{
        name: 'scanhexa',
        script: 'server.js',
        cwd: '/home/user/scanhexa',
        env: {
            NODE_ENV: 'production',
            PORT: 3000
        },
        watch: false,
        instances: 1,
        exec_mode: 'fork',
        max_memory_restart: '512M'
    }]
};