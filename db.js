// db.js
const mysql = require('mysql2');


/*
const pool = mysql.createPool({    
    host: '162.240.233.237',   // IP de tu VPS o jartnash.com si apunta al VPS
    port: 22022,                // Aseg�rate de especificar el puerto si es distinto del 3306
    user: 'root',
    password: 'Sologmedic.12345',
    database: 'sologmedic_database',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    decimalNumbers: true
});
*/

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
