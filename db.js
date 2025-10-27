// db.js
const mysql = require('mysql2');

/* Servidor
const pool = mysql.createPool({
    host: '162.240.178.133',   // IP de tu VPS o jartnash.com si apunta al VPS
    port: 3306,                // Aseg�rate de especificar el puerto si es distinto del 3306
    user: 'jartnash_root',
    password: 'Sologmedic.12345',
    database: 'jartnash_programa',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    decimalNumbers: true
});*/


const pool = mysql.createPool({
    host: '127.0.0.1',   // IP de tu VPS o jartnash.com si apunta al VPS
    port: 3306,                // Aseg�rate de especificar el puerto si es distinto del 3306
    user: 'root',
    password: '12345678',
    database: 'jartnash_programa',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    decimalNumbers: true
});

module.exports = pool.promise();
