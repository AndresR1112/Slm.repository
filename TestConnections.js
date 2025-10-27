const pool = require('./db');

async function testConnection() {
  try {
    const [rows] = await pool.query('SHOW DATABASES;');
    console.log('Conexión exitosa. Bases de datos disponibles:');
    console.table(rows);
    process.exit(0);
  } catch (err) {
    console.error('Error al conectarse a la base de datos:', err);
    process.exit(1);
  }
}

testConnection();
