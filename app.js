// app.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const ExcelJS = require('exceljs');
const db = require('./db');
const multer = require('multer');
const bcrypt = require('bcryptjs'); // <- Encriptar contraseñas

const app = express();

/* ===== Configuración base ===== */
app.set('views', path.join(__dirname, 'views'));   // <- ¡clave! usa la carpeta correcta
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'NashiR',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 }
}));

/* ===== Middlewares de sesión/rol ===== */
function estaLogueado(req, res, next) {
  if (req.session?.usuario) return next();
  return res.redirect('/acceso');
}

// Normaliza el tipo de usuario: minúsculas, sin espacios y con guión bajo
function getTipoUsuario(req) {
  const t = req.session?.usuario?.tipo_usuario;
  const normalizado = (t || '')
    .toString()
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_'); // "Recursos humanos " -> "recursos_humanos"

  console.log('👉 tipo_usuario crudo:', t, '→ normalizado:', normalizado);
  return normalizado;
}

function esAdmin(req, res, next) {
  const tipo = getTipoUsuario(req);
  if (tipo === 'administrador') return next();
  return res.redirect('/catalogo');
}

// Admin O Recursos Humanos (muy tolerante)
function esAdminORH(req, res, next) {
  const raw = (req.session?.usuario?.tipo_usuario || '').toString();
  const tipo = raw.trim().toLowerCase().replace(/\s+/g, '_');

  console.log('👉 esAdminORH - tipo_usuario crudo:', raw, '→ normalizado:', tipo);

  if (
    tipo === 'administrador' ||
    tipo === 'recursos_humanos' ||
    tipo === 'rh' ||
    tipo.includes('recurso') // "recursos humanos", "recurso humano", etc.
  ) {
    return next();
  }

  return res.redirect('/catalogo');
}

// Middleware genérico por rol
function requireRol(...roles) {
  return function (req, res, next) {
    const tipo = getTipoUsuario(req);
    if (roles.includes(tipo)) {
      return next();
    }
    console.log('🚫 Acceso denegado. Rol:', tipo, 'Necesario uno de:', roles);
    return res.status(403).send('No tienes permisos para realizar esta acción.');
  };
}

// === Cliente 3PL: solo puede ver sus módulos ===
function esCliente(req, res, next) {
  if (!req.session?.usuario) {
    return res.redirect('/acceso');
  }

  const tipo = getTipoUsuario(req);

  if (tipo === 'cliente') {
    const idCli = req.session.usuario.id_cliente;
    if (!idCli) {
      console.log('⚠ Cliente logueado sin id_cliente en sesión');
    } else {
      console.log('👤 Cliente 3PL, id_cliente =', idCli);
      req.idCliente = idCli;
    }
    return next();
  }

  console.log('🚫 Acceso solo para clientes 3PL. Rol actual:', tipo);
  return res.status(403).send('No tienes permisos para ver este módulo.');
}

// === Solo internos (admin, almacén, etc). Bloquea a cliente 3PL ===
function soloInterno(req, res, next) {
  const tipo = getTipoUsuario(req);
  if (tipo === 'cliente') {
    console.log('🚫 Usuario cliente intentó acceder a un módulo interno');
    return res.status(403).send('No tienes permisos para ver este módulo.');
  }
  return next();
}

// Permisos por módulo (ajustables según tus reglas)
const puedeEditarCatalogo = requireRol('administrador', 'almacen');
const puedeEditarEntradas = requireRol('administrador', 'almacen');
const puedeEditarSalidas = requireRol('administrador', 'almacen');
const puedeEditarClientes = requireRol('administrador', 'facturacion');
const puedeEditarCotizaciones = requireRol('administrador', 'cotizacion');

/* ======================================================
   CONFIGURACIÓN DE MULTER PARA SUBIDA DE ARCHIVOS
   ====================================================== */

// Configuración de almacenamiento
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const modulo = req.params.modulo;  // entradas, salidas, cotizaciones, facturacion, usuarios
    const id = req.params.id;          // id de la fila

    let folder;
    switch (modulo) {
      case 'entradas': folder = 'entradas'; break;
      case 'salidas': folder = 'salidas'; break;
      case 'cotizaciones': folder = 'cotizaciones'; break;
      case 'facturacion': folder = 'facturacion'; break;
      case 'usuarios': folder = 'usuarios'; break;
      default: folder = 'otros';
    }

    const uploadPath = path.join(__dirname, 'uploads', folder, String(id));
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },

  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext);
    const safeBase = base.replace(/[^a-zA-Z0-9_-]/g, '_');
    cb(null, `${safeBase}_${timestamp}${ext}`);
  }
});

// Por ahora solo PDFs, luego podemos abrir a más tipos
function fileFilter(req, file, cb) {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Solo se permiten archivos PDF'), false);
  }
}

const upload = multer({ storage, fileFilter });

/* ======================================================
   RUTAS GENERALES DE ARCHIVOS ADJUNTOS
   ====================================================== */
// DESCARGAR ARCHIVO (internos + clientes 3PL)
app.get('/adjuntos/descargar/:id_archivo', estaLogueado, async (req, res) => {
  const idArchivo = parseInt(req.params.id_archivo, 10);
  if (isNaN(idArchivo)) {
    return res.status(400).send('ID de archivo inválido');
  }

  try {
    const [rows] = await db.query(
      `SELECT * FROM archivo_adjunto WHERE id_archivo = ?`,
      [idArchivo]
    );

    if (!rows.length) {
      return res.status(404).send('Archivo no encontrado');
    }

    const archivo = rows[0];

    // 🔒 Si es archivo de USUARIO, solo Admin o RH pueden descargar
    if (archivo.modulo === 'usuario') {
      const tipo = getTipoUsuario(req);  // asumiendo que ya tienes esta función definida
      if (!(tipo === 'administrador' || tipo === 'recursos_humanos')) {
        return res.status(403).send('No tienes permisos para descargar archivos de usuarios.');
      }
    }

    // Para el resto de módulos (entrada, salida, etc.) basta con estar logueado.
    const filePath = path.join(__dirname, archivo.ruta_archivo);

    res.download(filePath, archivo.nombre_original, (err) => {
      if (err) {
        console.error('Error al descargar archivo:', err);
        if (!res.headersSent) {
          res.status(500).send('Error al descargar archivo');
        }
      }
    });
  } catch (err) {
    console.error('Error al descargar archivo:', err);
    res.status(500).send('Error al descargar archivo');
  }
});


app.post('/adjuntos/eliminar/:id_archivo', estaLogueado, soloInterno, async (req, res) => {
  const idArchivo = parseInt(req.params.id_archivo, 10);
  if (isNaN(idArchivo)) {
    return res.status(400).send('ID de archivo inválido');
  }

  try {
    const [rows] = await db.query(
      `SELECT * FROM archivo_adjunto WHERE id_archivo = ?`,
      [idArchivo]
    );

    if (!rows.length) {
      return res.status(404).send('Archivo no encontrado');
    }

    const archivo = rows[0];

    // 🔒 Si es archivo de usuario, solo admin o RH pueden eliminar
    if (archivo.modulo === 'usuario') {
      const tipo = getTipoUsuario(req);
      if (!(tipo === 'administrador' || tipo === 'recursos_humanos')) {
        return res.status(403).send('No tienes permisos para eliminar archivos de usuarios.');
      }
    }

    // 1) Borrar en BD
    await db.query(`DELETE FROM archivo_adjunto WHERE id_archivo = ?`, [idArchivo]);

    // 2) Borrar archivo físico
    const filePath = path.join(__dirname, archivo.ruta_archivo);
    fs.unlink(filePath, (err) => {
      if (err) console.error('No se pudo borrar archivo físico:', err);
    });

    // 3) Redirigir al módulo correspondiente
    let redirect;
    switch (archivo.modulo) {
      case 'entrada': redirect = '/entradas'; break;
      case 'salida': redirect = '/salidas'; break;
      case 'cotizacion': redirect = '/cotizaciones'; break;
      case 'facturacion': redirect = '/facturacion'; break;
      case 'usuario': redirect = '/usuarios'; break;
      default: redirect = '/';
    }

    res.redirect(redirect);
  } catch (err) {
    console.error('Error al eliminar archivo adjunto:', err);
    res.status(500).send('Error al eliminar archivo adjunto');
  }
});

app.post('/adjuntos/subir/:modulo/:id',
  estaLogueado,
  soloInterno,
  upload.array('archivos', 10),
  async (req, res) => {
    const moduloParam = req.params.modulo;  // entradas, salidas, cotizaciones, facturacion, usuarios
    const idRegistro = parseInt(req.params.id, 10);
    const usuario = req.session.usuario;

    if (isNaN(idRegistro)) {
      console.error('ID de registro inválido en adjuntos:', req.params.id);
      return res.status(400).send('ID de registro inválido');
    }

    let moduloDb;
    switch (moduloParam) {
      case 'entradas': moduloDb = 'entrada'; break;
      case 'salidas': moduloDb = 'salida'; break;
      case 'cotizaciones': moduloDb = 'cotizacion'; break;
      case 'facturacion': moduloDb = 'facturacion'; break;
      case 'usuarios': moduloDb = 'usuario'; break;
      default:
        console.error('Módulo no válido en adjuntos:', moduloParam);
        return res.status(400).send('Módulo no válido');
    }

    // 🔒 Si es módulo usuarios, solo admin o RH pueden subir
    if (moduloDb === 'usuario') {
      const tipo = getTipoUsuario(req);
      if (!(tipo === 'administrador' || tipo === 'recursos_humanos')) {
        return res.status(403).send('No tienes permisos para subir archivos de usuarios.');
      }
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).send('No se recibieron archivos');
    }

    try {
      for (const file of req.files) {
        const rutaRelativa = path
          .relative(__dirname, file.path)
          .replace(/\\/g, '/');

        await db.query(
          `
            INSERT INTO archivo_adjunto
              (modulo, id_registro, nombre_original, nombre_sistema, mime_type, peso_bytes, ruta_archivo, usuario_fk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            moduloDb,
            idRegistro,
            file.originalname,
            file.filename,
            file.mimetype,
            file.size,
            rutaRelativa,
            usuario ? usuario.id_usuario : null
          ]
        );
      }

      const redirects = {
        entradas: '/entradas',
        salidas: '/salidas',
        cotizaciones: '/cotizaciones',
        facturacion: '/facturacion',
        usuarios: '/usuarios'
      };

      res.redirect(redirects[moduloParam] || '/');
    } catch (err) {
      console.error('Error guardando archivos adjuntos:', err);
      res.status(500).send('Error al guardar archivos adjuntos');
    }
  }
);


// SUBIR ARCHIVOS SOLO PARA ENTRADAS
app.post('/adjuntos/entradas/:id_entrada',
  estaLogueado,
  soloInterno,
  upload.array('archivos', 10),
  async (req, res) => {
    const idEntrada = parseInt(req.params.id_entrada, 10);
    if (isNaN(idEntrada)) {
      console.error('ID de entrada inválido:', req.params.id_entrada);
      return res.status(400).send('ID de entrada inválido');
    }

    const usuario = req.session.usuario;

    try {
      if (!req.files || req.files.length === 0) {
        return res.redirect('/entradas');
      }

      for (const file of req.files) {
        const rutaRelativa = path
          .relative(__dirname, file.path)
          .replace(/\\/g, '/');

        await db.query(
          `
            INSERT INTO archivo_adjunto
              (modulo, id_registro, nombre_original, nombre_sistema, mime_type, peso_bytes, ruta_archivo, usuario_fk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            'entrada',
            idEntrada,
            file.originalname,
            file.filename,
            file.mimetype,
            file.size,
            rutaRelativa,
            usuario ? usuario.id_usuario : null
          ]
        );
      }

      res.redirect('/entradas');
    } catch (err) {
      console.error('Error guardando archivos adjuntos (entradas):', err);
      res.status(500).send('Error al guardar archivos adjuntos');
    }
  }
);

// SUBIR ARCHIVOS SOLO PARA SALIDAS
app.post('/adjuntos/salidas/:id_salida',
  estaLogueado,
  soloInterno,
  upload.array('archivos', 10),
  async (req, res) => {
    const idSalida = parseInt(req.params.id_salida, 10);
    if (isNaN(idSalida)) {
      console.error('ID de salida inválido:', req.params.id_salida);
      return res.status(400).send('ID de salida inválido');
    }

    const usuario = req.session.usuario;

    try {
      if (!req.files || req.files.length === 0) {
        return res.redirect('/salidas');
      }

      for (const file of req.files) {
        const rutaRelativa = path
          .relative(__dirname, file.path)
          .replace(/\\/g, '/');

        await db.query(
          `
            INSERT INTO archivo_adjunto
              (modulo, id_registro, nombre_original, nombre_sistema, mime_type, peso_bytes, ruta_archivo, usuario_fk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            'salida',
            idSalida,
            file.originalname,
            file.filename,
            file.mimetype,
            file.size,
            rutaRelativa,
            usuario ? usuario.id_usuario : null
          ]
        );
      }

      res.redirect('/salidas');
    } catch (err) {
      console.error('Error guardando archivos adjuntos (salidas):', err);
      res.status(500).send('Error al guardar archivos adjuntos');
    }
  }
);

/* ===== Rutas de acceso / login ===== */
app.get('/', (req, res) => req.session.destroy(() => res.redirect('/acceso')));

app.get('/acceso', (req, res) => {
  res.render('acceso', { error: null });
});

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    // Primero buscamos solo por userName
    const [results] = await db.query(
      `SELECT * FROM usuario
       WHERE BINARY TRIM(userName) = ?`,
      [usuario]
    );

    if (!results.length) {
      return res.render('acceso', { error: 'Usuario o contraseña incorrectos' });
    }

    const user = results[0];
    const hashEnBD = user['contraseña_usuario'];

    let esValida = false;

    if (hashEnBD && hashEnBD.startsWith('$2')) {
      // Contraseña ya encriptada (bcrypt)
      esValida = await bcrypt.compare(password, hashEnBD);
    } else {
      // Contraseña en texto plano en BD → comparamos directo
      if (password === hashEnBD) {
        esValida = true;
        // Opcional: migrar a bcrypt automáticamente
        try {
          const nuevoHash = await bcrypt.hash(password, 10);
          await db.query(
            'UPDATE usuario SET `contraseña_usuario` = ? WHERE id_usuario = ?',
            [nuevoHash, user.id_usuario]
          );
          user['contraseña_usuario'] = nuevoHash;
        } catch (e) {
          console.error('Error migrando contraseña a bcrypt:', e);
        }
      } else {
        esValida = false;
      }
    }

    if (!esValida) {
      return res.render('acceso', { error: 'Usuario o contraseña incorrectos' });
    }

    // NORMALIZACIÓN DEL ROL
    user.tipo_usuario = user.tipo_usuario
      .toString()
      .trim()
      .toLowerCase()
      .replace(/\s+/g, '_');

    // Guardamos todo el usuario en sesión (incluye id_cliente si lo tiene)
    req.session.usuario = user;

    // 🔀 Redirección según tipo de usuario
    if (user.tipo_usuario === 'cliente') {
      // Cliente 3PL → solo panel 3PL
      return res.redirect('/cliente');
    } else {
      // Usuarios internos → panel de Sologmedic
      return res.redirect('/catalogo');
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Error en el servidor');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/acceso'));
});

/* ======================================================
/* ===== Usuarios ===== */
app.get('/usuarios', estaLogueado, esAdmin, async (req, res) => {
  try {
    // Usuarios (con posible id_cliente)
    const [usuarios] = await db.query(`
      SELECT u.*, c.nombre_cliente
      FROM usuario u
      LEFT JOIN cliente c ON u.id_cliente = c.id_cliente
      ORDER BY u.userName ASC
    `);

    // Adjuntos del módulo "usuario"
    const [adjuntos] = await db.query(
      `SELECT * FROM archivo_adjunto WHERE modulo = 'usuario'`
    );

    const adjuntosPorUsuario = {};
    adjuntos.forEach(a => {
      if (!adjuntosPorUsuario[a.id_registro]) {
        adjuntosPorUsuario[a.id_registro] = [];
      }
      adjuntosPorUsuario[a.id_registro].push(a);
    });

    res.render('usuario', {
      usuarios,
      usuario: req.session.usuario,
      adjuntosPorUsuario
    });
  } catch (err) {
    console.error(err);
    res.send('Error cargando usuarios');
  }
});

/* ===== Nuevo Usuario ===== */
app.get('/usuarios/nuevo', estaLogueado, esAdmin, async (req, res) => {
  try {
    const [clientes3pl] = await db.query(`
      SELECT id_cliente, nombre_cliente
      FROM cliente
      WHERE es_3pl = 1
      ORDER BY nombre_cliente ASC
    `);

    res.render('editar_usuario', {
      usuarioData: {},
      editar: false,
      usuario: req.session.usuario,
      error: null,
      clientes3pl
    });
  } catch (err) {
    console.error('Error cargando formulario de nuevo usuario:', err);
    res.send('Error al cargar formulario de usuario');
  }
});

app.post('/usuarios/nuevo', estaLogueado, esAdmin, async (req, res) => {
  let {
    userName,
    nombreCompleto,
    tipo_usuario,
    telefono_usuario,
    correo_usuario,
    contraseña_usuario,
    id_cliente
  } = req.body;

  // Normalizar tipo de usuario
  tipo_usuario = tipo_usuario.trim().toLowerCase().replace(/\s+/g, '_');

  // Si no es tipo "cliente", no asignamos id_cliente
  if (tipo_usuario !== 'cliente') {
    id_cliente = null;
  }

  try {
    const [existente] = await db.query(
      'SELECT * FROM usuario WHERE BINARY TRIM(userName) = ?',
      [userName]
    );
    if (existente.length > 0) {
      // Volvemos a cargar lista de clientes 3PL para el form
      const [clientes3pl] = await db.query(`
        SELECT id_cliente, nombre_cliente
        FROM cliente
        WHERE es_3pl = 1
        ORDER BY nombre_cliente ASC
      `);

      return res.render('editar_usuario', {
        usuarioData: req.body,
        editar: false,
        usuario: req.session.usuario,
        error: 'El nombre de usuario ya existe',
        clientes3pl
      });
    }

    const hash = await bcrypt.hash(contraseña_usuario, 10);

    await db.query(
      `INSERT INTO usuario
        (userName, nombreCompleto, tipo_usuario,
         telefono_usuario, correo_usuario, \`contraseña_usuario\`,
         fechaRegistro_usuario, id_cliente)
       VALUES (?, ?, ?, ?, ?, ?, CURDATE(), ?)`,
      [userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, hash, id_cliente]
    );

    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al agregar usuario');
  }
});

/* ===== Editar Usuario ===== */
app.get('/usuarios/editar/:id', estaLogueado, esAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const [results] = await db.query('SELECT * FROM usuario WHERE id_usuario = ?', [id]);
    if (!results.length) {
      return res.send('Usuario no encontrado');
    }

    const [clientes3pl] = await db.query(`
      SELECT id_cliente, nombre_cliente
      FROM cliente
      WHERE es_3pl = 1
      ORDER BY nombre_cliente ASC
    `);

    res.render('editar_usuario', {
      usuarioData: results[0],
      editar: true,
      usuario: req.session.usuario,
      error: null,
      clientes3pl
    });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar usuario');
  }
});

app.post('/usuarios/editar/:id', estaLogueado, esAdmin, async (req, res) => {
  const id = req.params.id;

  let {
    userName,
    nombreCompleto,
    tipo_usuario,
    telefono_usuario,
    correo_usuario,
    contraseña_usuario,
    id_cliente
  } = req.body;

  tipo_usuario = tipo_usuario.trim().toLowerCase().replace(/\s+/g, '_');

  if (tipo_usuario !== 'cliente') {
    id_cliente = null;
  }

  try {
    // Obtener contraseña actual
    const [[actual]] = await db.query(
      'SELECT `contraseña_usuario` FROM usuario WHERE id_usuario = ?',
      [id]
    );
    if (!actual) {
      return res.send('Usuario no encontrado');
    }

    let passwordToSave;
    if (contraseña_usuario && contraseña_usuario.trim() !== '') {
      passwordToSave = await bcrypt.hash(contraseña_usuario, 10);
    } else {
      passwordToSave = actual['contraseña_usuario'];
    }

    await db.query(
      `UPDATE usuario
         SET userName          = ?,
             nombreCompleto    = ?,
             tipo_usuario      = ?,
             telefono_usuario  = ?,
             correo_usuario    = ?,
             \`contraseña_usuario\` = ?,
             id_cliente        = ?
       WHERE id_usuario = ?`,
      [userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, passwordToSave, id_cliente, id]
    );

    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al actualizar usuario');
  }
});

/* ===== Eliminar Usuario ===== */
app.post('/usuarios/eliminar/:id', estaLogueado, esAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM usuario WHERE id_usuario = ?', [req.params.id]);
    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al eliminar usuario');
  }
});

/* ===== Rutas 3PL (cliente laboratorio) ===== */

// DASHBOARD 3PL
app.get('/cliente', estaLogueado, esCliente, async (req, res) => {
  try {
    const idCliente = req.idCliente; // id_cliente del laboratorio (ej. Synthon = 8)

    const [[resumen]] = await db.query(
      `
      SELECT 
        COUNT(*) AS total_registros,
        COALESCE(SUM(stock_inventario), 0) AS total_piezas
      FROM inventario
      WHERE id_cliente_propietario = ?
      `,
      [idCliente]
    );

    res.render('dashboard3pl', {
      usuario: req.session.usuario,
      resumen
    });
  } catch (err) {
    console.error('Error en /cliente:', err);
    res.status(500).send('Error al cargar dashboard 3PL');
  }
});

/* ======================================================
   3PL – ENTRADAS, INVENTARIO Y SALIDAS PARA CLIENTES
   ====================================================== */
/* ===== Entradas 3PL (cliente) ===== */
app.get('/cliente/entradas', estaLogueado, async (req, res) => {
  try {
    const usuario   = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    // Filtros desde querystring
    const {
      mes,        // número 1-12
      anio,       // año 2024, etc.
      producto,   // id_catalogo
      lote,
      cantidad,
      q           // buscador general
    } = req.query;

    const where  = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (mes) {
      where.push('MONTH(e.fechaDeEntrada) = ?');
      params.push(Number(mes));
    }
    if (anio) {
      where.push('YEAR(e.fechaDeEntrada) = ?');
      params.push(Number(anio));
    }
    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('e.lote = ?');
      params.push(lote);
    }
    if (cantidad) {
      where.push('e.cantidad = ?');
      params.push(Number(cantidad));
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          c.clave_catalogo       LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR e.lote              LIKE ?
          OR CAST(e.cantidad AS CHAR) LIKE ?
        )
      `);
      params.push(like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [entradas] = await db.query(
      `
      SELECT
        e.id_entrada,
        e.fechaDeEntrada,
        e.lote,
        e.caducidad,
        e.cantidad,
        e.costoTotal_entrada,
        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo
      FROM entrada e
      JOIN inventario i
        ON e.producto_FKdeInv = i.id_inventario
      JOIN catalogo c
        ON i.producto_FKinventario = c.id_catalogo
      ${whereSql}
      ORDER BY e.fechaDeEntrada DESC, c.clave_catalogo ASC
      `,
      params
    );

    // ===== Adjuntos por entrada (solo lectura en 3PL) =====
    let adjuntosPorEntrada = {};
    if (entradas.length > 0) {
      const idsEntradas = entradas.map(e => e.id_entrada);

      const [adjuntos] = await db.query(
        `
        SELECT *
        FROM archivo_adjunto
        WHERE modulo = 'entrada'
          AND id_registro IN (?)
        `,
        [idsEntradas]
      );

      for (const a of adjuntos) {
        if (!adjuntosPorEntrada[a.id_registro]) {
          adjuntosPorEntrada[a.id_registro] = [];
        }
        adjuntosPorEntrada[a.id_registro].push(a);
      }
    }

    // ==== Datos para combos de filtro (solo con base en lo que tiene este cliente) ====

    // Meses/Años disponibles
    const [filtrosFecha] = await db.query(
      `
      SELECT DISTINCT
        YEAR(e.fechaDeEntrada)  AS anio,
        MONTH(e.fechaDeEntrada) AS mes
      FROM entrada e
      JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      WHERE i.id_cliente_propietario = ?
      ORDER BY anio DESC, mes DESC
      `,
      [clienteId]
    );

    // Productos disponibles
    const [filtrosProductos] = await db.query(
      `
      SELECT DISTINCT
        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo
      FROM entrada e
      JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      JOIN catalogo c   ON i.producto_FKinventario = c.id_catalogo
      WHERE i.id_cliente_propietario = ?
      ORDER BY c.nombreProdu_catalogo ASC
      `,
      [clienteId]
    );

    // Lotes (con info de producto)
    const [filtrosLotes] = await db.query(
      `
      SELECT DISTINCT
        i.lote_inventario AS lote,
        i.producto_FKinventario AS id_catalogo
      FROM inventario i
      JOIN catalogo c
        ON c.id_catalogo = i.producto_FKinventario
      WHERE i.id_cliente_propietario = ?
      ORDER BY i.lote_inventario ASC
      `,
      [clienteId]
    );

    // Cantidades distintas, ligadas a producto/lote
    const [filtrosCantidades] = await db.query(
      `
      SELECT DISTINCT
        e.cantidad,
        c.id_catalogo,
        e.lote
      FROM entrada e
      JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      JOIN catalogo c   ON i.producto_FKinventario = c.id_catalogo
      WHERE i.id_cliente_propietario = ?
      ORDER BY e.cantidad ASC
      `,
      [clienteId]
    );

    // Querystring para export (si quieres respetar filtros en el Excel)
    const qsParts = [];
    if (mes)      qsParts.push('mes=' + encodeURIComponent(mes));
    if (anio)     qsParts.push('anio=' + encodeURIComponent(anio));
    if (producto) qsParts.push('producto=' + encodeURIComponent(producto));
    if (lote)     qsParts.push('lote=' + encodeURIComponent(lote));
    if (cantidad) qsParts.push('cantidad=' + encodeURIComponent(cantidad));
    if (q && q.trim() !== '') qsParts.push('q=' + encodeURIComponent(q.trim()));
    const qsExport = qsParts.length ? ('?' + qsParts.join('&')) : '';

    res.render('3pl_entradas', {
      entradas,
      filtrosFecha,
      filtrosProductos,
      filtrosLotes,
      filtrosCantidades,
      filtrosSeleccionados: {
        mes: mes || '',
        anio: anio || '',
        producto: producto || '',
        lote: lote || '',
        cantidad: cantidad || '',
        q: q || ''
      },
      adjuntosPorEntrada,
      qsExport,
      q,
      usuario
    });
  } catch (err) {
    console.error('Error cargando entradas 3PL:', err);
    res.send('Error cargando entradas 3PL');
  }
});


/* ===== Inventario 3PL (cliente) ===== */
app.get('/cliente/inventario', estaLogueado, async (req, res) => {
  try {
    const usuario = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    const {
      producto,
      lote,
      stock,
      estado,
      q
    } = req.query;

    const where = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('i.lote_inventario = ?');
      params.push(lote);
    }
    if (stock) {
      where.push('i.stock_inventario = ?');
      params.push(Number(stock));
    }
    if (estado) {
      where.push(`
        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END = ?
      `);
      params.push(estado);
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          c.clave_catalogo LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR i.lote_inventario LIKE ?
          OR CAST(i.stock_inventario AS CHAR) LIKE ?
          OR
            CASE
              WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
              WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
              WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
              ELSE 'Vigente'
            END LIKE ?
        )
      `);
      params.push(like, like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [inventario] = await db.query(
      `
      SELECT
        i.id_inventario,
        i.producto_FKinventario,
        i.lote_inventario,
        i.stock_inventario,
        i.caducidad_inventario,
        DATEDIFF(i.caducidad_inventario, CURDATE()) AS diasRestantes_inventario,

        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo,

        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END AS estadoDelProducto_inventario
      FROM inventario i
      JOIN catalogo c ON i.producto_FKinventario = c.id_catalogo
      ${whereSql}
      ORDER BY i.caducidad_inventario ASC, c.clave_catalogo ASC
      `,
      params
    );

    // Combos para filtros

    const [filtrosProductos] = await db.query(
      `
      SELECT DISTINCT
        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo
      FROM inventario i
      JOIN catalogo c ON i.producto_FKinventario = c.id_catalogo
      WHERE i.id_cliente_propietario = ?
      ORDER BY c.nombreProdu_catalogo ASC
      `,
      [clienteId]
    );

    const [filtrosLotes] = await db.query(
      `
      SELECT DISTINCT
        i.lote_inventario       AS lote,
        i.producto_FKinventario AS id_catalogo
      FROM inventario i
      JOIN catalogo c ON c.id_catalogo = i.producto_FKinventario
      WHERE i.id_cliente_propietario = ?
      ORDER BY i.lote_inventario ASC
      `,
      [clienteId]
    );

    const [filtrosStock] = await db.query(
      `
      SELECT DISTINCT i.stock_inventario AS stock
      FROM inventario i
      WHERE i.id_cliente_propietario = ?
      ORDER BY i.stock_inventario ASC
      `,
      [clienteId]
    );

    const [filtrosEstados] = await db.query(
      `
      SELECT DISTINCT
        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END AS estado
      FROM inventario i
      WHERE i.id_cliente_propietario = ?
      `,
      [clienteId]
    );

    res.render('3pl_inventario', {
      inventario,
      filtrosProductos,
      filtrosLotes,
      filtrosStock,
      filtrosEstados,
      filtrosSeleccionados: {
        producto: producto || '',
        lote: lote || '',
        stock: stock || '',
        estado: estado || '',
        q: q || ''
      },
      usuario
    });
  } catch (err) {
    console.error('Error cargando inventario 3PL:', err);
    res.send('Error cargando inventario 3PL');
  }
});

/* ===== Salidas 3PL (cliente) ===== */
app.get('/cliente/salidas', estaLogueado, async (req, res) => {
  try {
    const usuario   = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    const {
      orden,
      producto,
      lote,
      cantidad,
      cliente_destino,
      q
    } = req.query;

    const where  = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (orden) {
      where.push('s.ordenDeCompra_salida = ?');
      params.push(orden);
    }
    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('s.lote = ?');
      params.push(lote);
    }
    if (cantidad) {
      where.push('s.cantidad = ?');
      params.push(Number(cantidad));
    }
    if (cliente_destino) {
      where.push('cliDestino.id_cliente = ?');
      params.push(Number(cliente_destino));
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          s.ordenDeCompra_salida   LIKE ?
          OR c.clave_catalogo       LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR s.lote                 LIKE ?
          OR CAST(s.cantidad AS CHAR) LIKE ?
          OR cliDestino.nombre_cliente LIKE ?
        )
      `);
      params.push(like, like, like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [salidas] = await db.query(
      `
      SELECT
        s.id_salida,
        s.ordenDeCompra_salida,
        s.fecha_salida,
        s.lote,
        s.cantidad,
        s.totalFacturado_salida,
        s.folioDeFacturacion_salida,

        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo,

        cliDestino.id_cliente     AS id_cliente_destino,
        cliDestino.nombre_cliente AS cliente_destino
      FROM salida s
      JOIN inventario i  ON s.id_inventario = i.id_inventario
      JOIN catalogo  c   ON i.producto_FKinventario = c.id_catalogo
      LEFT JOIN cliente cliDestino
        ON s.id_cliente = cliDestino.id_cliente
      ${whereSql}
      ORDER BY s.fecha_salida DESC, c.clave_catalogo ASC
      `,
      params
    );

    // ===== Adjuntos por salida (solo lectura en 3PL) =====
    let adjuntosPorSalida = {};
    if (salidas.length > 0) {
      const idsSalidas = salidas.map(s => s.id_salida);

      const [adjuntos] = await db.query(
        `
        SELECT *
        FROM archivo_adjunto
        WHERE modulo = 'salida'
          AND id_registro IN (?)
        `,
        [idsSalidas]
      );

      for (const a of adjuntos) {
        if (!adjuntosPorSalida[a.id_registro]) {
          adjuntosPorSalida[a.id_registro] = [];
        }
        adjuntosPorSalida[a.id_registro].push(a);
      }
    }

    // Filtros para combos
    const [filtrosOrdenes] = await db.query(
      `
      SELECT DISTINCT s.ordenDeCompra_salida AS orden
      FROM salida s
      JOIN inventario i ON s.id_inventario = i.id_inventario
      WHERE i.id_cliente_propietario = ?
      ORDER BY s.ordenDeCompra_salida ASC
      `,
      [clienteId]
    );

    const [filtrosProductos] = await db.query(
      `
      SELECT DISTINCT
        c.id_catalogo,
        c.clave_catalogo,
        c.nombreProdu_catalogo
      FROM salida s
      JOIN inventario i ON s.id_inventario = i.id_inventario
      JOIN catalogo  c  ON i.producto_FKinventario = c.id_catalogo
      WHERE i.id_cliente_propietario = ?
      ORDER BY c.nombreProdu_catalogo ASC
      `,
      [clienteId]
    );

    const [filtrosLotes] = await db.query(
      `
      SELECT DISTINCT
        i.lote_inventario AS lote,
        i.producto_FKinventario AS id_catalogo
      FROM salida s
      JOIN inventario i ON i.id_inventario = s.id_inventario
      JOIN catalogo c   ON c.id_catalogo   = i.producto_FKinventario
      WHERE i.id_cliente_propietario = ?
      ORDER BY i.lote_inventario ASC
      `,
      [clienteId]
    );

    const [filtrosCantidades] = await db.query(
      `
      SELECT DISTINCT
        s.cantidad,
        c.id_catalogo,
        i.lote_inventario AS lote
      FROM salida s
      JOIN inventario i ON s.id_inventario = i.id_inventario
      JOIN catalogo  c  ON i.producto_FKinventario = c.id_catalogo
      WHERE i.id_cliente_propietario = ?
      ORDER BY s.cantidad ASC
      `,
      [clienteId]
    );

    const [filtrosClientesDestino] = await db.query(
      `
      SELECT DISTINCT
        cliDestino.id_cliente,
        cliDestino.nombre_cliente
      FROM salida s
      JOIN inventario i ON s.id_inventario = i.id_inventario
      LEFT JOIN cliente cliDestino ON s.id_cliente = cliDestino.id_cliente
      WHERE i.id_cliente_propietario = ?
        AND cliDestino.id_cliente IS NOT NULL
      ORDER BY cliDestino.nombre_cliente ASC
      `,
      [clienteId]
    );

    // Querystring para export
    const qsParts = [];
    if (orden)           qsParts.push('orden=' + encodeURIComponent(orden));
    if (producto)        qsParts.push('producto=' + encodeURIComponent(producto));
    if (lote)            qsParts.push('lote=' + encodeURIComponent(lote));
    if (cantidad)        qsParts.push('cantidad=' + encodeURIComponent(cantidad));
    if (cliente_destino) qsParts.push('cliente_destino=' + encodeURIComponent(cliente_destino));
    if (q && q.trim() !== '') qsParts.push('q=' + encodeURIComponent(q.trim()));
    const qsExport = qsParts.length ? ('?' + qsParts.join('&')) : '';

    res.render('3pl_salidas', {
      salidas,
      filtrosOrdenes,
      filtrosProductos,
      filtrosLotes,
      filtrosCantidades,
      filtrosClientesDestino,
      filtrosSeleccionados: {
        orden: orden || '',
        producto: producto || '',
        lote: lote || '',
        cantidad: cantidad || '',
        cliente_destino: cliente_destino || '',
        q: q || ''
      },
      adjuntosPorSalida,
      qsExport,
      q,
      usuario
    });
  } catch (err) {
    console.error('Error cargando salidas 3PL:', err);
    res.send('Error cargando salidas 3PL');
  }
});


/* ===== Exportar ENTRADAS 3PL a Excel ===== */
app.get('/cliente/entradas/exportar', estaLogueado, async (req, res) => {
  try {
    const usuario   = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    const {
      mes,
      anio,
      producto,
      lote,
      cantidad,
      q
    } = req.query;

    const where  = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (mes) {
      where.push('MONTH(e.fechaDeEntrada) = ?');
      params.push(Number(mes));
    }
    if (anio) {
      where.push('YEAR(e.fechaDeEntrada) = ?');
      params.push(Number(anio));
    }
    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('e.lote = ?');
      params.push(lote);
    }
    if (cantidad) {
      where.push('e.cantidad = ?');
      params.push(Number(cantidad));
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          c.clave_catalogo       LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR e.lote              LIKE ?
          OR CAST(e.cantidad AS CHAR) LIKE ?
        )
      `);
      params.push(like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [rows] = await db.query(
      `
      SELECT
        e.fechaDeEntrada AS Fecha,
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS Producto,
        e.lote           AS Lote,
        e.caducidad      AS Caducidad,
        e.cantidad       AS Cantidad,
        e.costoTotal_entrada AS Costo_Total
      FROM entrada e
      JOIN inventario i
        ON e.producto_FKdeInv = i.id_inventario
      JOIN catalogo c
        ON i.producto_FKinventario = c.id_catalogo
      ${whereSql}
      ORDER BY e.fechaDeEntrada DESC, c.clave_catalogo ASC
      `,
      params
    );

    const workbook  = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Entradas');

    worksheet.columns = [
      { header: 'Fecha',       key: 'Fecha',       width: 12 },
      { header: 'Producto',    key: 'Producto',    width: 45 },
      { header: 'Lote',        key: 'Lote',        width: 15 },
      { header: 'Caducidad',   key: 'Caducidad',   width: 12 },
      { header: 'Cantidad',    key: 'Cantidad',    width: 12 },
      { header: 'Costo Total', key: 'Costo_Total', width: 15 }
    ];

    rows.forEach(r => worksheet.addRow(r));
    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=entradas.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando entradas 3PL a Excel:', err);
    res.status(500).send('Error exportando entradas 3PL a Excel');
  }
});

/* ===== Exportar INVENTARIO 3PL a Excel ===== */
app.get('/cliente/inventario/exportar', estaLogueado, async (req, res) => {
  try {
    const usuario   = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    const {
      producto,
      lote,
      stock,
      estado,
      q
    } = req.query;

    const where  = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('i.lote_inventario = ?');
      params.push(lote);
    }
    if (stock) {
      where.push('i.stock_inventario = ?');
      params.push(Number(stock));
    }
    if (estado) {
      where.push(`
        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END = ?
      `);
      params.push(estado);
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          c.clave_catalogo LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR i.lote_inventario LIKE ?
          OR CAST(i.stock_inventario AS CHAR) LIKE ?
          OR
            CASE
              WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
              WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
              WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
              ELSE 'Vigente'
            END LIKE ?
        )
      `);
      params.push(like, like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [rows] = await db.query(
      `
      SELECT
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS Producto,
        i.lote_inventario      AS Lote,
        i.stock_inventario     AS Stock,
        i.caducidad_inventario AS Caducidad,
        DATEDIFF(i.caducidad_inventario, CURDATE()) AS Dias_restantes,
        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END AS Estado
      FROM inventario i
      JOIN catalogo c ON i.producto_FKinventario = c.id_catalogo
      ${whereSql}
      ORDER BY i.caducidad_inventario ASC, c.clave_catalogo ASC
      `,
      params
    );

    const workbook  = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Inventario');

    worksheet.columns = [
      { header: 'Producto',       key: 'Producto',       width: 45 },
      { header: 'Lote',           key: 'Lote',           width: 15 },
      { header: 'Stock',          key: 'Stock',          width: 12 },
      { header: 'Caducidad',      key: 'Caducidad',      width: 12 },
      { header: 'Días restantes', key: 'Dias_restantes', width: 16 },
      { header: 'Estado',         key: 'Estado',         width: 18 }
    ];

    rows.forEach(r => worksheet.addRow(r));
    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=inventario.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando inventario 3PL a Excel:', err);
    res.status(500).send('Error exportando inventario 3PL a Excel');
  }
});

/* ===== Exportar SALIDAS 3PL a Excel ===== */
app.get('/cliente/salidas/exportar', estaLogueado, async (req, res) => {
  try {
    const usuario   = req.session.usuario;
    const clienteId = usuario.id_cliente;

    if (!clienteId) {
      return res.status(403).send('Tu usuario no tiene un cliente asociado para 3PL.');
    }

    const {
      orden,
      producto,
      lote,
      cantidad,
      cliente_destino,
      q
    } = req.query;

    const where  = ['i.id_cliente_propietario = ?'];
    const params = [clienteId];

    if (orden) {
      where.push('s.ordenDeCompra_salida = ?');
      params.push(orden);
    }
    if (producto) {
      where.push('c.id_catalogo = ?');
      params.push(Number(producto));
    }
    if (lote) {
      where.push('s.lote = ?');
      params.push(lote);
    }
    if (cantidad) {
      where.push('s.cantidad = ?');
      params.push(Number(cantidad));
    }
    if (cliente_destino) {
      where.push('cliDestino.id_cliente = ?');
      params.push(Number(cliente_destino));
    }
    if (q && q.trim() !== '') {
      const like = `%${q.trim()}%`;
      where.push(`
        (
          s.ordenDeCompra_salida LIKE ?
          OR c.clave_catalogo    LIKE ?
          OR c.nombreProdu_catalogo LIKE ?
          OR s.lote              LIKE ?
          OR CAST(s.cantidad AS CHAR) LIKE ?
          OR cliDestino.nombre_cliente LIKE ?
        )
      `);
      params.push(like, like, like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const [rows] = await db.query(
      `
      SELECT
        s.ordenDeCompra_salida                              AS Orden_de_compra,
        s.fecha_salida                                      AS Fecha,
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS Producto,
        s.lote                                              AS Lote,
        s.cantidad                                          AS Cantidad,
        cliDestino.nombre_cliente                           AS Cliente_destino,
        s.totalFacturado_salida                             AS Total_facturado,
        s.folioDeFacturacion_salida                         AS Folio_factura
      FROM salida s
      JOIN inventario i  ON s.id_inventario = i.id_inventario
      JOIN catalogo  c   ON i.producto_FKinventario = c.id_catalogo
      LEFT JOIN cliente cliDestino
        ON s.id_cliente = cliDestino.id_cliente
      ${whereSql}
      ORDER BY s.fecha_salida DESC, c.clave_catalogo ASC
      `,
      params
    );

    const workbook  = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Salidas');

    worksheet.columns = [
      { header: 'Orden de compra', key: 'Orden_de_compra',  width: 18 },
      { header: 'Fecha',           key: 'Fecha',            width: 12 },
      { header: 'Producto',        key: 'Producto',         width: 45 },
      { header: 'Lote',            key: 'Lote',             width: 15 },
      { header: 'Cantidad',        key: 'Cantidad',         width: 12 },
      { header: 'Cliente destino', key: 'Cliente_destino',  width: 30 },
      { header: 'Total facturado', key: 'Total_facturado',  width: 18 },
      { header: 'Folio factura',   key: 'Folio_factura',    width: 20 }
    ];

    rows.forEach(r => worksheet.addRow(r));
    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=salidas.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando salidas 3PL a Excel:', err);
    res.status(500).send('Error exportando salidas 3PL a Excel');
  }
});


/* ===== Reporte PDF de inventario usando hoja base en TODAS las páginas ===== */
app.get('/reporte', estaLogueado, soloInterno, async (req, res) => {
  try {
    // 1) Consulta con los nombres de la BD nueva
    const [rows] = await db.query(`
      SELECT
        ca.nombreProdu_catalogo        AS Producto,
        i.lote_inventario              AS Lote,
        i.stock_inventario             AS Stock,
        i.caducidad_inventario         AS Caducidad,
        i.diasRestantes_inventario     AS Dias_Restantes,
        i.estadoDelProducto_inventario AS Estado
      FROM inventario i
      LEFT JOIN catalogo ca
        ON ca.id_catalogo = i.producto_FKinventario
      ORDER BY ca.nombreProdu_catalogo ASC, i.caducidad_inventario ASC
    `);

    // 2) Carga de la hoja base (plantilla)
    const plantillaPath = path.join(__dirname, 'public', 'hojaBase.pdf');
    if (!fs.existsSync(plantillaPath)) {
      console.error('No se encontró la plantilla en:', plantillaPath);
      return res.status(404).send("Plantilla PDF no encontrada");
    }
    const plantillaBytes = fs.readFileSync(plantillaPath);

    const outPdf = await PDFDocument.create();
    const basePdf = await PDFDocument.load(plantillaBytes);
    const font = await outPdf.embedFont(StandardFonts.Helvetica);

    const addTemplatePage = async () => {
      const [tpl] = await outPdf.copyPages(basePdf, [0]);
      return outPdf.addPage(tpl);
    };

    let page = await addTemplatePage();
    let { width, height } = page.getSize();

    const columnas = ["Producto", "Lote", "Stock", "Caducidad", "Días Restantes", "Estado"];
    const colWidths = [140, 70, 50, 90, 90, 90];
    const rowHeight = 25;
    const startX = 50;
    const topMargin = 180;
    const bottomMargin = 50;

    let startY = height - topMargin;

    const fmtFecha = (v) => {
      if (!v) return "";
      if (v instanceof Date) return v.toISOString().split('T')[0];
      const s = String(v);
      return s.length >= 10 ? s.slice(0, 10) : s;
    };
    const toStr = (v) => (v === null || v === undefined ? "" : String(v));

    const drawRow = (arr, isHeader = false) => {
      let x = startX;
      for (let j = 0; j < arr.length; j++) {
        if (isHeader) {
          page.drawRectangle({
            x, y: startY - rowHeight, width: colWidths[j], height: rowHeight,
            color: rgb(0, 0.2, 0.6)
          });
        } else {
          page.drawRectangle({
            x, y: startY - rowHeight, width: colWidths[j], height: rowHeight,
            borderColor: rgb(0, 0, 0), borderWidth: 1
          });
        }

        const text = toStr(arr[j]);
        const maxChars = Math.max(1, Math.floor((colWidths[j] - 6) / 5.5));
        const shown = text.length > maxChars ? text.slice(0, maxChars - 1) + '…' : text;

        page.drawText(shown, {
          x: x + 3,
          y: startY - rowHeight + 7,
          size: 10,
          font,
          color: isHeader ? rgb(1, 1, 1) : rgb(0, 0, 0),
        });

        x += colWidths[j];
      }
      startY -= rowHeight;
    };

    const newPageWithHeader = async () => {
      page = await addTemplatePage();
      ({ width, height } = page.getSize());
      startY = height - 60;
      drawRow(columnas, true);
    };

    drawRow(columnas, true);

    for (const r of rows) {
      if (startY - rowHeight < bottomMargin) {
        await newPageWithHeader();
      }
      const fila = [
        r.Producto || "",
        toStr(r.Lote),
        toStr(r.Stock),
        fmtFecha(r.Caducidad),
        toStr(r.Dias_Restantes),
        r.Estado || ""
      ];
      drawRow(fila, false);
    }

    const pdfBytes = await outPdf.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=Inventario.pdf');
    res.send(Buffer.from(pdfBytes));
  } catch (err) {
    console.error("Error en /reporte:", err);
    res.status(500).send("Error al generar el reporte PDF");
  }
});

/* ===== Catálogo ===== */

// LISTADO PRINCIPAL DE CATALOGO
app.get('/catalogo', estaLogueado, async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT 
        id_catalogo,
        clave_catalogo,
        nombreProdu_catalogo,
        presentacion_catalogo,
        claveSSA_catalogo,
        precioVenta_catalogo,
        costoUnitario_catalogo
      FROM catalogo
      ORDER BY clave_catalogo ASC
    `);

    res.render('catalogo', {
      catalogo: results,
      usuario: req.session.usuario,
      q: ''  // para que el input de búsqueda no truene
    });

  } catch (err) {
    console.error('Error al cargar catálogo:', err);
    res.send('Error al cargar catálogo');
  }
});

// EXPORTAR CATALOGO A EXCEL
app.get('/catalogo/exportar', estaLogueado, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        clave_catalogo         AS Clave,
        nombreProdu_catalogo   AS Nombre,
        presentacion_catalogo  AS Presentacion,
        claveSSA_catalogo      AS Clave_SSA,
        precioVenta_catalogo   AS Precio_Venta,
        costoUnitario_catalogo AS Costo_Unitario
      FROM catalogo
      ORDER BY clave_catalogo ASC
    `);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Catálogo');

    worksheet.columns = [
      { header: 'Clave', key: 'Clave', width: 18 },
      { header: 'Nombre', key: 'Nombre', width: 50 },
      { header: 'Presentación', key: 'Presentacion', width: 25 },
      { header: 'Clave SSA', key: 'Clave_SSA', width: 18 },
      { header: 'Precio Venta', key: 'Precio_Venta', width: 15 },
      { header: 'Costo Unitario', key: 'Costo_Unitario', width: 15 }
    ];

    rows.forEach(row => worksheet.addRow(row));
    worksheet.getRow(1).font = { bold: true };

    const nombreArchivo = 'catalogo.xlsx';

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=${nombreArchivo}`
    );

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error('Error exportando catálogo a Excel:', err);
    res.status(500).send('Error al exportar catálogo');
  }
});

// Buscar en catálogo por clave, clave SSA o nombre
app.get('/catalogo/buscar', estaLogueado, async (req, res) => {
  const q = req.query.q?.toString().trim();
  if (!q) return res.redirect('/catalogo');

  try {
    const [results] = await db.query(
      `
      SELECT *
      FROM catalogo
      WHERE clave_catalogo = ?
         OR claveSSA_catalogo = ?
         OR nombreProdu_catalogo LIKE CONCAT('%', ?, '%')
      ORDER BY nombreProdu_catalogo ASC
      `,
      [q, q, q]
    );

    res.render('catalogo', {
      catalogo: results,
      usuario: req.session.usuario,
      q
    });
  } catch (err) {
    console.error('Error buscando en catálogo:', err);
    res.send('Error buscando en catálogo');
  }
});

app.get('/catalogo/nuevo', estaLogueado, puedeEditarCatalogo, (req, res) => {
  res.render('editar_catalogo', { medicamento: null, usuario: req.session.usuario });
});

app.post('/catalogo/nuevo', estaLogueado, puedeEditarCatalogo, async (req, res) => {
  const { clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo } = req.body;
  try {
    await db.query(
      `INSERT INTO catalogo (clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, parseFloat(precioVenta_catalogo), parseFloat(costoUnitario_catalogo)]
    );
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al agregar medicamento');
  }
});

app.get('/catalogo/editar/:id', estaLogueado, puedeEditarCatalogo, async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM catalogo WHERE id_catalogo = ?', [req.params.id]);
    if (!results.length) return res.send('Medicamento no encontrado');
    res.render('editar_catalogo', { medicamento: results[0], usuario: req.session.usuario });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar medicamento');
  }
});

app.post('/catalogo/editar/:id', estaLogueado, puedeEditarCatalogo, async (req, res) => {
  const { clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo } = req.body;
  try {
    await db.query(
      `UPDATE catalogo
         SET clave_catalogo = ?, nombreProdu_catalogo = ?, presentacion_catalogo = ?, claveSSA_catalogo = ?, precioVenta_catalogo = ?, costoUnitario_catalogo = ?
       WHERE id_catalogo = ?`,
      [clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, parseFloat(precioVenta_catalogo), parseFloat(costoUnitario_catalogo), req.params.id]
    );
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al actualizar medicamento');
  }
});

app.post('/catalogo/eliminar/:id', estaLogueado, puedeEditarCatalogo, async (req, res) => {
  try {
    const [result] = await db.query('DELETE FROM catalogo WHERE id_catalogo = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.send('Medicamento no encontrado');
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al eliminar medicamento, verifica que no esté en uso');
  }
});

/* ===== Entradas ===== */
app.get('/entradas', estaLogueado, soloInterno, async (req, res) => {
  try {
    const [entrada] = await db.query(`
      SELECT 
        e.*,
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS ProductoNombre,
        i.lote_inventario              AS LoteInventario,
        i.estadoDelProducto_inventario AS EstadoInv,
        cli.nombre_cliente             AS PropietarioNombre
      FROM entrada e
      LEFT JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      LEFT JOIN catalogo  c  ON i.producto_FKinventario = c.id_catalogo
      LEFT JOIN cliente   cli ON e.id_cliente_propietario = cli.id_cliente
      ORDER BY e.fechaDeEntrada DESC, c.clave_catalogo ASC
    `);

    const idsEntradas = entrada.map(e => e.id_entrada);
    let adjuntosPorEntrada = {};

    if (idsEntradas.length > 0) {
      const [adjuntos] = await db.query(
        `
          SELECT *
          FROM archivo_adjunto
          WHERE modulo = 'entrada'
            AND id_registro IN (?)
        `,
        [idsEntradas]
      );

      adjuntos.forEach(a => {
        if (!adjuntosPorEntrada[a.id_registro]) {
          adjuntosPorEntrada[a.id_registro] = [];
        }
        adjuntosPorEntrada[a.id_registro].push(a);
      });
    }

    res.render('entradas', {
      entrada,
      adjuntosPorEntrada,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando entradas:', err);
    res.send('Error cargando entradas');
  }
});

/* 🔹 Exportar ENTRADAS a Excel */
app.get('/entradas/exportar', estaLogueado, soloInterno, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        e.fechaDeEntrada           AS Fecha,
        e.proveedor                AS Proveedor,
        c.clave_catalogo           AS Clave,
        c.nombreProdu_catalogo     AS Producto,
        e.lote                     AS Lote,
        e.caducidad                AS Caducidad,
        e.cantidad                 AS Cantidad,
        e.costoTotal_entrada       AS Costo_Total
      FROM entrada e
      LEFT JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      LEFT JOIN catalogo  c  ON i.producto_FKinventario = c.id_catalogo
      ORDER BY e.fechaDeEntrada DESC, c.clave_catalogo ASC
    `);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Entradas');

    worksheet.columns = [
      { header: 'Fecha', key: 'Fecha', width: 12 },
      { header: 'Proveedor', key: 'Proveedor', width: 25 },
      { header: 'Clave', key: 'Clave', width: 18 },
      { header: 'Producto', key: 'Producto', width: 45 },
      { header: 'Lote', key: 'Lote', width: 15 },
      { header: 'Caducidad', key: 'Caducidad', width: 12 },
      { header: 'Cantidad', key: 'Cantidad', width: 12 },
      { header: 'Costo Total', key: 'Costo_Total', width: 15 }
    ];

    rows.forEach(row => worksheet.addRow(row));
    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=entradas.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando entradas a Excel:', err);
    res.status(500).send('Error al exportar entradas');
  }
});

/* ===== Buscador de entradas ===== */
app.get('/entradas/buscar', estaLogueado, soloInterno, async (req, res) => {
  const q = (req.query.q || '').toString().trim();
  if (!q) return res.redirect('/entradas');

  try {
    const [entrada] = await db.query(
      `
      SELECT 
        e.*,
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS ProductoNombre,
        i.lote_inventario              AS LoteInventario,
        i.estadoDelProducto_inventario AS EstadoInv,
        cli.nombre_cliente             AS PropietarioNombre
      FROM entrada e
      LEFT JOIN inventario i ON e.producto_FKdeInv = i.id_inventario
      LEFT JOIN catalogo  c  ON i.producto_FKinventario = c.id_catalogo
      LEFT JOIN cliente   cli ON e.id_cliente_propietario = cli.id_cliente
      WHERE 
        e.proveedor LIKE CONCAT('%', ?, '%')
        OR e.lote LIKE CONCAT('%', ?, '%')
        OR c.nombreProdu_catalogo LIKE CONCAT('%', ?, '%')
        OR c.clave_catalogo LIKE CONCAT('%', ?, '%')
        OR c.claveSSA_catalogo LIKE CONCAT('%', ?, '%')
      ORDER BY e.fechaDeEntrada DESC
      `,
      [q, q, q, q, q]
    );

    const idsEntradas = entrada.map(e => e.id_entrada);
    let adjuntosPorEntrada = {};

    if (idsEntradas.length > 0) {
      const [adjuntos] = await db.query(
        `
          SELECT *
          FROM archivo_adjunto
          WHERE modulo = 'entrada'
            AND id_registro IN (?)
        `,
        [idsEntradas]
      );

      adjuntos.forEach(a => {
        if (!adjuntosPorEntrada[a.id_registro]) {
          adjuntosPorEntrada[a.id_registro] = [];
        }
        adjuntosPorEntrada[a.id_registro].push(a);
      });
    }

    res.render('entradas', {
      entrada,
      usuario: req.session.usuario,
      q,
      adjuntosPorEntrada
    });
  } catch (err) {
    console.error('Error buscando entradas:', err);
    res.send('Error buscando entradas');
  }
});

/* ===== Nueva entrada (form) ===== */
app.get('/entradas/nueva', estaLogueado, puedeEditarEntradas, async (req, res) => {
  try {
    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, nombreProdu_catalogo
      FROM catalogo
      ORDER BY nombreProdu_catalogo ASC
    `);

    const [clientes] = await db.query(`
      SELECT id_cliente, nombre_cliente
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    const entrada = {
      Id: 0,
      Proveedor: '',
      Fecha: new Date(),
      Lote: '',
      Caducidad: '',
      Cantidad: '',
      CostoTotal: '',
      ProductoId: null,
      id_cliente_propietario: null
    };

    res.render('editar_entrada', {
      editar: false,
      entrada,
      productos,
      clientes,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando productos/clientes:', err);
    res.send('Error cargando productos/clientes');
  }
});

/* ===== Nueva entrada (POST) ===== */
app.post('/entradas/nueva', estaLogueado, puedeEditarEntradas, async (req, res) => {
  const {
    Fecha_de_entrada,
    Proveedor,
    Producto,
    Lote,
    Caducidad,
    Cantidad,
    Costo_Total,
    id_cliente_propietario
  } = req.body;

  const idClienteProp = id_cliente_propietario || null;

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[productoExiste]] = await conn.query(
      'SELECT id_catalogo FROM catalogo WHERE id_catalogo = ?',
      [Producto]
    );
    if (!productoExiste) {
      await conn.rollback();
      return res.send('❌ Error: El producto no existe en el catálogo.');
    }

    const [[invExiste]] = await conn.query(
      `SELECT id_inventario
         FROM inventario
        WHERE producto_FKinventario = ? AND lote_inventario = ?
        FOR UPDATE`,
      [Producto, Lote]
    );

    let inventarioId;
    if (invExiste) {
      inventarioId = invExiste.id_inventario;
      await conn.query(
        `UPDATE inventario
            SET stock_inventario = stock_inventario + ?,
                caducidad_inventario = ?,
                diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                estadoDelProducto_inventario = 'Disponible',
                id_cliente_propietario = ?
          WHERE id_inventario = ?`,
        [Number(Cantidad), Caducidad, Caducidad, idClienteProp, inventarioId]
      );
    } else {
      const [nuevoInv] = await conn.query(
        `INSERT INTO inventario
          (producto_FKinventario,
           lote_inventario,
           stock_inventario,
           caducidad_inventario,
           diasRestantes_inventario,
           estadoDelProducto_inventario,
           id_cliente_propietario)
         VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible', ?)`,
        [Producto, Lote, Number(Cantidad), Caducidad, Caducidad, idClienteProp]
      );
      inventarioId = nuevoInv.insertId;
    }

    await conn.query(
      `INSERT INTO entrada
        (proveedor,
         fechaDeEntrada,
         lote,
         caducidad,
         cantidad,
         costoTotal_entrada,
         producto_FKdeInv,
         id_cliente_propietario)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        Proveedor,
        Fecha_de_entrada,
        Lote,
        Caducidad,
        Number(Cantidad),
        Costo_Total,
        inventarioId,
        idClienteProp
      ]
    );

    await conn.commit();
    res.redirect('/entradas');
  } catch (err) {
    await conn.rollback();
    console.error('Error al agregar entrada:', err);
    res.send('Error al agregar entrada');
  } finally {
    conn.release();
  }
});

/* ===== Editar entrada (form) ===== */
app.get('/entradas/editar/:id', estaLogueado, puedeEditarEntradas, async (req, res) => {
  const entradaId = req.params.id;
  try {
    const [[entrada]] = await db.query(`
      SELECT
        e.id_entrada             AS Id,
        e.proveedor              AS Proveedor,
        e.fechaDeEntrada         AS Fecha,
        e.lote                   AS Lote,
        e.caducidad              AS Caducidad,
        e.cantidad               AS Cantidad,
        e.costoTotal_entrada     AS CostoTotal,
        i.producto_FKinventario  AS ProductoId,
        e.id_cliente_propietario AS id_cliente_propietario
      FROM entrada e
      LEFT JOIN inventario i ON i.id_inventario = e.producto_FKdeInv
      WHERE e.id_entrada = ?
    `, [entradaId]);

    if (!entrada) return res.send('Entrada no encontrada');

    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, nombreProdu_catalogo
      FROM catalogo
      ORDER BY nombreProdu_catalogo ASC
    `);

    const [clientes] = await db.query(`
      SELECT id_cliente, nombre_cliente
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    res.render('editar_entrada', {
      editar: true,
      entrada,
      productos,
      clientes,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando entrada para editar:', err);
    res.send('Error cargando entrada');
  }
});

/* ===== Editar entrada (POST) ===== */
app.post('/entradas/editar/:id', estaLogueado, puedeEditarEntradas, async (req, res) => {
  const entradaId = req.params.id;
  const {
    Fecha_de_entrada,
    Proveedor,
    Producto,
    Lote,
    Caducidad,
    Cantidad,
    Costo_Total,
    id_cliente_propietario
  } = req.body;

  const idClienteProp = id_cliente_propietario || null;

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[entradaAnterior]] = await conn.query(
      'SELECT * FROM entrada WHERE id_entrada = ? FOR UPDATE',
      [entradaId]
    );
    if (!entradaAnterior) {
      await conn.rollback();
      return res.send('Entrada original no encontrada');
    }

    const [[invViejo]] = await conn.query(
      'SELECT * FROM inventario WHERE id_inventario = ? FOR UPDATE',
      [entradaAnterior.producto_FKdeInv]
    );
    if (!invViejo) {
      await conn.rollback();
      return res.send('Inventario original no encontrado');
    }

    const mismoProducto = (Number(invViejo.producto_FKinventario) === Number(Producto));
    const mismoLote = (invViejo.lote_inventario === Lote);

    if (mismoProducto && mismoLote) {
      // ✅ Siempre actualizamos inventario aunque delta sea 0,
      // para sincronizar id_cliente_propietario, caducidad, etc.
      const delta = Number(Cantidad) - Number(entradaAnterior.cantidad);

      await conn.query(
        `UPDATE inventario
            SET stock_inventario = stock_inventario + ?,
                caducidad_inventario = ?,
                diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                id_cliente_propietario = ?,
                estadoDelProducto_inventario = 'Disponible'
          WHERE id_inventario = ?`,
        [delta, Caducidad, Caducidad, idClienteProp, invViejo.id_inventario]
      );

      await conn.query(
        `UPDATE entrada
            SET proveedor = ?,
                fechaDeEntrada = ?,
                lote = ?,
                caducidad = ?,
                cantidad = ?,
                costoTotal_entrada = ?,
                id_cliente_propietario = ?
          WHERE id_entrada = ?`,
        [
          Proveedor,
          Fecha_de_entrada,
          Lote,
          Caducidad,
          Number(Cantidad),
          Costo_Total,
          idClienteProp,
          entradaId
        ]
      );
    } else {
      // Cambió producto y/o lote → mover stock a otro inventario
      const [[invDestinoExistente]] = await conn.query(
        `SELECT id_inventario
           FROM inventario
          WHERE producto_FKinventario = ? AND lote_inventario = ?
          FOR UPDATE`,
        [Producto, Lote]
      );

      let inventarioDestinoId;
      if (invDestinoExistente) {
        inventarioDestinoId = invDestinoExistente.id_inventario;
        await conn.query(
          `UPDATE inventario
              SET stock_inventario = stock_inventario + ?,
                  caducidad_inventario = ?,
                  diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                  estadoDelProducto_inventario = 'Disponible',
                  id_cliente_propietario = ?
            WHERE id_inventario = ?`,
          [Number(Cantidad), Caducidad, Caducidad, idClienteProp, inventarioDestinoId]
        );
      } else {
        const [nuevoInv] = await conn.query(
          `INSERT INTO inventario
            (producto_FKinventario,
             lote_inventario,
             stock_inventario,
             caducidad_inventario,
             diasRestantes_inventario,
             estadoDelProducto_inventario,
             id_cliente_propietario)
           VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible', ?)`,
          [Producto, Lote, Number(Cantidad), Caducidad, Caducidad, idClienteProp]
        );
        inventarioDestinoId = nuevoInv.insertId;
      }

      await conn.query(
        `UPDATE entrada
            SET proveedor = ?,
                fechaDeEntrada = ?,
                lote = ?,
                caducidad = ?,
                cantidad = ?,
                costoTotal_entrada = ?,
                producto_FKdeInv = ?,
                id_cliente_propietario = ?
          WHERE id_entrada = ?`,
        [
          Proveedor,
          Fecha_de_entrada,
          Lote,
          Caducidad,
          Number(Cantidad),
          Costo_Total,
          inventarioDestinoId,
          idClienteProp,
          entradaId
        ]
      );

      // Restar del inventario viejo
      await conn.query(
        `UPDATE inventario
            SET stock_inventario = stock_inventario - ?
          WHERE id_inventario = ?`,
        [Number(entradaAnterior.cantidad), invViejo.id_inventario]
      );

      const [[revViejo]] = await conn.query(
        'SELECT stock_inventario FROM inventario WHERE id_inventario = ?',
        [invViejo.id_inventario]
      );
      if (revViejo && Number(revViejo.stock_inventario) === 0) {
        const [[refsViejas]] = await conn.query(
          'SELECT COUNT(*) AS cnt FROM entrada WHERE producto_FKdeInv = ?',
          [invViejo.id_inventario]
        );

        if (Number(refsViejas.cnt) === 0) {
          await conn.query('DELETE FROM inventario WHERE id_inventario = ?', [invViejo.id_inventario]);
        } else {
          await conn.query(
            `UPDATE inventario
                SET estadoDelProducto_inventario = 'Agotado'
              WHERE id_inventario = ?`,
            [invViejo.id_inventario]
          );
        }
      }
    }

    await conn.commit();
    res.redirect('/entradas');
  } catch (err) {
    await conn.rollback();
    console.error('Error editando entrada:', err);
    res.send('Error editando entrada');
  } finally {
    conn.release();
  }
});
/* ======================================================
   SALIDAS (MÓDULO INTERNO Sologmedic)
   ====================================================== */

/* ===== Listado de salidas ===== */
app.get('/salidas', estaLogueado, soloInterno, async (req, res) => {
  try {
    const [salidas] = await db.query(`
      SELECT
        s.id_salida                  AS Id,
        s.ordenDeCompra_salida      AS orden_de_compra,
        s.fecha_salida              AS Fecha,
        cl.nombre_cliente           AS ClienteNombre,

        CONCAT('(', ca.clave_catalogo, ') ',
               TRIM(REPLACE(ca.nombreProdu_catalogo, CONCAT('(', ca.clave_catalogo, ')'), '')))
          AS ProductoNombre,

        ca.clave_catalogo           AS Codigo,
        s.lote                      AS Lote,
        s.cantidad                  AS Cantidad,
        s.precioDeVenta_salida      AS Precio_Venta,
        s.totalFacturado_salida     AS Total_Facturado,
        s.folioDeFacturacion_salida AS Folio_de_Facturacion,
        s.id_cliente_propietario    AS id_cliente_propietario
      FROM salida s
      LEFT JOIN cliente    cl ON cl.id_cliente   = s.id_cliente
      LEFT JOIN inventario i  ON i.id_inventario = s.id_inventario
      LEFT JOIN catalogo   ca ON ca.id_catalogo  = i.producto_FKinventario
      ORDER BY s.fecha_salida DESC, ca.clave_catalogo ASC
    `);

    const [adjuntos] = await db.query(
      `SELECT * FROM archivo_adjunto WHERE modulo = 'salida'`
    );

    const adjuntosPorSalida = {};
    for (const a of adjuntos) {
      if (!adjuntosPorSalida[a.id_registro]) {
        adjuntosPorSalida[a.id_registro] = [];
      }
      adjuntosPorSalida[a.id_registro].push(a);
    }

    res.render('salidas', {
      salidas,
      adjuntosPorSalida,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando salidas:', err);
    res.send('Error cargando salidas');
  }
});

/* 🔹 Exportar SALIDAS a Excel */
app.get('/salidas/exportar', estaLogueado, soloInterno, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
        s.fecha_salida              AS Fecha,
        s.ordenDeCompra_salida      AS Orden_de_compra,
        cl.nombre_cliente           AS Cliente,
        CONCAT('(', ca.clave_catalogo, ') ',
               TRIM(REPLACE(ca.nombreProdu_catalogo, CONCAT('(', ca.clave_catalogo, ')'), '')))
          AS Producto,
        ca.clave_catalogo           AS Codigo,
        s.lote                      AS Lote,
        s.cantidad                  AS Cantidad,
        s.precioDeVenta_salida      AS Precio_Venta,
        s.totalFacturado_salida     AS Total_Facturado,
        s.folioDeFacturacion_salida AS Folio_de_Facturacion
      FROM salida s
      LEFT JOIN cliente    cl ON cl.id_cliente   = s.id_cliente
      LEFT JOIN inventario i  ON i.id_inventario = s.id_inventario
      LEFT JOIN catalogo   ca ON ca.id_catalogo  = i.producto_FKinventario
      ORDER BY s.fecha_salida DESC, ca.clave_catalogo ASC
    `);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Salidas');

    worksheet.columns = [
      { header: 'Fecha', key: 'Fecha', width: 12 },
      { header: 'Orden de compra', key: 'Orden_de_compra', width: 18 },
      { header: 'Cliente', key: 'Cliente', width: 30 },
      { header: 'Producto', key: 'Producto', width: 45 },
      { header: 'Clave', key: 'Codigo', width: 16 },
      { header: 'Lote', key: 'Lote', width: 15 },
      { header: 'Cantidad', key: 'Cantidad', width: 12 },
      { header: 'Precio Venta', key: 'Precio_Venta', width: 15 },
      { header: 'Total Facturado', key: 'Total_Facturado', width: 18 },
      { header: 'Folio de facturación', key: 'Folio_de_Facturacion', width: 22 }
    ];

    rows.forEach(row => worksheet.addRow(row));
    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=salidas.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando salidas a Excel:', err);
    res.status(500).send('Error al exportar salidas');
  }
});

/* 🔎 Buscar salida por OC (solo interno) */
app.get('/salidas/buscar', estaLogueado, soloInterno, async (req, res) => {
  const orden = req.query.orden_buscar?.toString().trim();
  if (!orden) return res.redirect('/salidas');

  try {
    const [salidas] = await db.query(`
      SELECT
        s.id_salida                  AS Id,
        s.ordenDeCompra_salida      AS orden_de_compra,
        s.fecha_salida              AS Fecha,
        cl.nombre_cliente           AS ClienteNombre,
        ca.nombreProdu_catalogo     AS ProductoNombre,
        ca.clave_catalogo           AS Codigo,
        s.lote                      AS Lote,
        s.cantidad                  AS Cantidad,
        s.precioDeVenta_salida      AS Precio_Venta,
        s.totalFacturado_salida     AS Total_Facturado,
        s.folioDeFacturacion_salida AS Folio_de_Facturacion,
        s.id_cliente_propietario    AS id_cliente_propietario
      FROM salida s
      LEFT JOIN cliente    cl ON cl.id_cliente   = s.id_cliente
      LEFT JOIN inventario i  ON i.id_inventario = s.id_inventario
      LEFT JOIN catalogo   ca ON ca.id_catalogo  = i.producto_FKinventario
      WHERE s.ordenDeCompra_salida = ?
      ORDER BY s.fecha_salida DESC
    `, [orden]);

    res.render('salidas', {
      salidas,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error buscando orden de compra:', err);
    res.send('Error buscando orden de compra');
  }
});

/* ===== Nueva salida (FORM) ===== */
app.get('/salidas/nueva', estaLogueado, puedeEditarSalidas, async (req, res) => {
  try {
    const [clientes] = await db.query(`
      SELECT id_cliente AS Id, nombre_cliente AS Nombre
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    const [productos] = await db.query(`
      SELECT
        c.clave_catalogo        AS Codigo,
        c.nombreProdu_catalogo  AS Nombre
      FROM inventario i
      JOIN catalogo c ON c.id_catalogo = i.producto_FKinventario
      WHERE i.stock_inventario > 0
      GROUP BY c.clave_catalogo, c.nombreProdu_catalogo
      ORDER BY c.nombreProdu_catalogo ASC
    `);

    const [lotes] = await db.query(`
      SELECT
        c.clave_catalogo        AS Producto,
        i.lote_inventario       AS Lote,
        i.caducidad_inventario  AS Caducidad,
        i.stock_inventario      AS Stock
      FROM inventario i
      JOIN catalogo c ON c.id_catalogo = i.producto_FKinventario
      WHERE i.stock_inventario > 0
      ORDER BY c.nombreProdu_catalogo ASC, i.lote_inventario ASC
    `);

    const salida = {
      Id: 0,
      orden_de_compra: '',
      Fecha: new Date(),
      ClienteId: null,
      Producto: '',
      Lote: '',
      Cantidad: '',
      Precio_Venta: '',
      Total_Facturado: '',
      Folio_de_Facturacion: ''
    };

    res.render('editar_salida', {
      salida,
      clientes,
      productos,
      lotes,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando formulario de nueva salida:', err);
    res.send('Error cargando formulario de nueva salida');
  }
});

/* ===== Nueva salida (POST) ===== */
app.post('/salidas/nueva', estaLogueado, puedeEditarSalidas, async (req, res) => {
  const conn = await db.getConnection();
  try {
    let {
      Fecha,
      ClienteId,
      Producto,
      Lote,
      Cantidad,
      Precio_Venta,
      Total_Facturado,
      orden_de_compra,
      Folio_de_Facturacion
    } = req.body;

    const cantidadNum = parseInt(Cantidad, 10);

    await conn.beginTransaction();

    // 1) Producto por clave_catalogo
    const [[cat]] = await conn.query(
      `SELECT id_catalogo FROM catalogo WHERE clave_catalogo = ?`,
      [Producto]
    );
    if (!cat) {
      await conn.rollback();
      return res.send(`
        <h2 style="color:red;">Error: Código de producto inválido</h2>
        <a href="/salidas/nueva"><button>Volver</button></a>
      `);
    }

    // 2) Inventario (incluyendo id_cliente_propietario)
    const [[inv]] = await conn.query(`
      SELECT
        id_inventario,
        stock_inventario,
        caducidad_inventario,
        id_cliente_propietario
      FROM inventario
      WHERE producto_FKinventario = ? AND lote_inventario = ?
      FOR UPDATE
    `, [cat.id_catalogo, Lote]);

    if (!inv || inv.stock_inventario < cantidadNum) {
      await conn.rollback();
      return res.send(`
        <h2 style="color:red;">Error: Stock insuficiente o lote inexistente</h2>
        <a href="/salidas/nueva"><button>Volver</button></a>
      `);
    }

    // 3) Consecutivo de orden de compra
    let ordenOC = (orden_de_compra && `${orden_de_compra}`.trim() !== '')
      ? `${orden_de_compra}`.trim()
      : null;

    if (!ordenOC) {
      const [[row]] = await conn.query(
        `SELECT * FROM consecutivo WHERE nombre = 'orden_de_compra' FOR UPDATE`
      );
      if (!row) {
        await conn.query(`
          INSERT INTO consecutivo (nombre, ultimoValor)
          VALUES ('orden_de_compra', 0)
        `);
      }
      const [[row2]] = await conn.query(
        `SELECT * FROM consecutivo WHERE nombre = 'orden_de_compra' FOR UPDATE`
      );
      const siguiente = Number(row2.ultimoValor) + 1;
      await conn.query(
        `UPDATE consecutivo SET ultimoValor = ? WHERE id_consecutivo = ?`,
        [siguiente, row2.id_consecutivo]
      );
      ordenOC = String(siguiente);
    }

    // 4) Insertar SALIDA con id_cliente_propietario tomado del inventario
    await conn.query(`
      INSERT INTO salida
        (ordenDeCompra_salida,
         fecha_salida,
         id_cliente,
         id_inventario,
         id_cliente_propietario,
         lote,
         cantidad,
         precioDeVenta_salida,
         totalFacturado_salida,
         folioDeFacturacion_salida)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      ordenOC,
      Fecha,
      ClienteId,
      inv.id_inventario,
      inv.id_cliente_propietario || null,
      Lote,
      cantidadNum,
      Precio_Venta,
      Total_Facturado,
      Folio_de_Facturacion || null
    ]);

    // 5) Actualizar inventario
    await conn.query(`
      UPDATE inventario
         SET stock_inventario = stock_inventario - ?,
             diasRestantes_inventario = DATEDIFF(caducidad_inventario, CURDATE())
       WHERE id_inventario = ?
    `, [cantidadNum, inv.id_inventario]);

    const [[rev]] = await conn.query(
      `SELECT stock_inventario FROM inventario WHERE id_inventario = ?`,
      [inv.id_inventario]
    );
    if (rev && Number(rev.stock_inventario) === 0) {
      await conn.query(
        `UPDATE inventario
            SET estadoDelProducto_inventario = 'Agotado'
          WHERE id_inventario = ?`,
        [inv.id_inventario]
      );
    }

    await conn.commit();
    res.redirect('/salidas');
  } catch (err) {
    await conn.rollback();
    console.error('Error procesando nueva salida:', err);
    res.send('Error procesando nueva salida');
  } finally {
    conn.release();
  }
});

/* ===== Editar salida (FORM) ===== */
app.get('/salidas/editar/:id', estaLogueado, puedeEditarSalidas, async (req, res) => {
  const salidaId = req.params.id;
  try {
    const [[salida]] = await db.query(`
      SELECT
        s.id_salida                  AS Id,
        s.ordenDeCompra_salida      AS orden_de_compra,
        s.fecha_salida              AS Fecha,
        s.id_cliente                AS ClienteId,
        ca.clave_catalogo           AS Producto,
        s.lote                      AS Lote,
        s.cantidad                  AS Cantidad,
        s.precioDeVenta_salida      AS Precio_Venta,
        s.totalFacturado_salida     AS Total_Facturado,
        s.folioDeFacturacion_salida AS Folio_de_Facturacion,
        s.id_inventario             AS id_inventario
      FROM salida s
      LEFT JOIN inventario i ON i.id_inventario = s.id_inventario
      LEFT JOIN catalogo  ca ON ca.id_catalogo   = i.producto_FKinventario
      WHERE s.id_salida = ?
    `, [salidaId]);

    if (!salida) return res.send('Salida no encontrada');

    const [clientes] = await db.query(`
      SELECT id_cliente AS Id, nombre_cliente AS Nombre
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    const [productos] = await db.query(`
      SELECT
        c.clave_catalogo        AS Codigo,
        c.nombreProdu_catalogo  AS Nombre
      FROM inventario i
      JOIN catalogo c ON c.id_catalogo = i.producto_FKinventario
      GROUP BY c.clave_catalogo, c.nombreProdu_catalogo
      ORDER BY c.nombreProdu_catalogo ASC
    `);

    const [lotes] = await db.query(`
      SELECT
        c.clave_catalogo        AS Producto,
        i.lote_inventario       AS Lote,
        i.caducidad_inventario  AS Caducidad,
        i.stock_inventario      AS Stock
      FROM inventario i
      JOIN catalogo c ON c.id_catalogo = i.producto_FKinventario
      WHERE (i.stock_inventario > 0) OR (i.id_inventario = ?)
      ORDER BY c.nombreProdu_catalogo ASC, i.lote_inventario ASC
    `, [salida.id_inventario]);

    res.render('editar_salida', {
      salida,
      clientes,
      productos,
      lotes,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando salida para editar:', err);
    res.send('Error cargando salida para editar');
  }
});

/* ===== Editar salida (POST) ===== */
app.post('/salidas/editar/:id', estaLogueado, puedeEditarSalidas, async (req, res) => {
  const salidaId = req.params.id;
  const conn = await db.getConnection();
  try {
    const {
      Fecha,
      ClienteId,
      Producto,
      Lote,
      Cantidad,
      Precio_Venta,
      Total_Facturado,
      orden_de_compra,
      Folio_de_Facturacion
    } = req.body;

    const nuevaCant = parseInt(Cantidad, 10);

    await conn.beginTransaction();

    // 1) Datos originales de la salida
    const [[original]] = await conn.query(`
      SELECT
        s.id_salida,
        s.cantidad              AS cant_original,
        s.id_inventario         AS inv_original,
        s.ordenDeCompra_salida  AS orden_original
      FROM salida s
      WHERE s.id_salida = ?
      FOR UPDATE
    `, [salidaId]);

    if (!original) {
      await conn.rollback();
      return res.send('Salida original no encontrada');
    }

    const cantOriginal = Number(original.cant_original || 0);

    // 2) Producto (id_catalogo)
    const [[cat]] = await conn.query(
      `SELECT id_catalogo FROM catalogo WHERE clave_catalogo = ?`,
      [Producto]
    );
    if (!cat) {
      await conn.rollback();
      return res.send(`
        <h2 style="color:red;">Error: Código de producto inválido</h2>
        <a href="/salidas"><button class="btn">Volver</button></a>
      `);
    }

    // 3) Inventario destino (con propietario)
    const [[invDestino]] = await conn.query(`
      SELECT
        id_inventario,
        stock_inventario,
        caducidad_inventario,
        id_cliente_propietario
      FROM inventario
      WHERE producto_FKinventario = ? AND lote_inventario = ?
      FOR UPDATE
    `, [cat.id_catalogo, Lote]);

    if (!invDestino) {
      await conn.rollback();
      return res.send(`
        <h2 style="color:red;">Error: Lote seleccionado no existe</h2>
        <a href="/salidas"><button class="btn">Volver</button></a>
      `);
    }

    const mismoInventario = (Number(invDestino.id_inventario) === Number(original.inv_original));

    // 4) Orden de compra final
    const ordenFinal = (orden_de_compra && `${orden_de_compra}`.trim() !== '')
      ? `${orden_de_compra}`.trim()
      : original.orden_original;

    if (mismoInventario) {
      // ===== MISMO INVENTARIO: sólo delta =====
      const stockActual = Number(invDestino.stock_inventario);
      const delta = nuevaCant - cantOriginal;

      if (delta > 0 && delta > stockActual) {
        await conn.rollback();
        return res.send(`
          <h2 style="color:red;">Error: La cantidad excede el stock disponible para este ajuste</h2>
          <a href="/salidas"><button class="btn">Volver</button></a>
        `);
      }

      const stockNuevo = stockActual - delta;

      await conn.query(
        `UPDATE inventario
            SET stock_inventario = ?
          WHERE id_inventario = ?`,
        [stockNuevo, invDestino.id_inventario]
      );

      await conn.query(`
        UPDATE salida
           SET fecha_salida = ?,
               id_cliente = ?,
               id_inventario = ?,
               id_cliente_propietario = ?,
               lote = ?,
               cantidad = ?,
               precioDeVenta_salida = ?,
               totalFacturado_salida = ?,
               ordenDeCompra_salida = ?,
               folioDeFacturacion_salida = ?
         WHERE id_salida = ?
      `, [
        Fecha,
        ClienteId,
        invDestino.id_inventario,
        invDestino.id_cliente_propietario || null,
        Lote,
        nuevaCant,
        Precio_Venta,
        Total_Facturado,
        ordenFinal,
        Folio_de_Facturacion || null,
        salidaId
      ]);
    } else {
      // ===== CAMBIO DE INVENTARIO =====

      // Regresar stock al inventario original
      if (original.inv_original) {
        await conn.query(
          `UPDATE inventario
              SET stock_inventario = stock_inventario + ?
            WHERE id_inventario = ?`,
          [cantOriginal, original.inv_original]
        );
      }

      // Validar stock en inventario destino
      if (Number(invDestino.stock_inventario) < nuevaCant) {
        await conn.rollback();
        return res.send(`
          <h2 style="color:red;">Error: Stock insuficiente en el nuevo lote seleccionado</h2>
          <a href="/salidas"><button class="btn">Volver</button></a>
        `);
      }

      // Descontar del inventario destino
      await conn.query(
        `UPDATE inventario
            SET stock_inventario = stock_inventario - ?
          WHERE id_inventario = ?`,
        [nuevaCant, invDestino.id_inventario]
      );

      // Actualizar salida
      await conn.query(`
        UPDATE salida
           SET fecha_salida = ?,
               id_cliente = ?,
               id_inventario = ?,
               id_cliente_propietario = ?,
               lote = ?,
               cantidad = ?,
               precioDeVenta_salida = ?,
               totalFacturado_salida = ?,
               ordenDeCompra_salida = ?,
               folioDeFacturacion_salida = ?
         WHERE id_salida = ?
      `, [
        Fecha,
        ClienteId,
        invDestino.id_inventario,
        invDestino.id_cliente_propietario || null,
        Lote,
        nuevaCant,
        Precio_Venta,
        Total_Facturado,
        ordenFinal,
        Folio_de_Facturacion || null,
        salidaId
      ]);

      // Si el inventario viejo queda en 0 → agotado
      if (original.inv_original) {
        const [[revViejo]] = await conn.query(
          `SELECT stock_inventario FROM inventario WHERE id_inventario = ?`,
          [original.inv_original]
        );
        if (revViejo && Number(revViejo.stock_inventario) === 0) {
          await conn.query(
            `UPDATE inventario
                SET estadoDelProducto_inventario = 'Agotado'
              WHERE id_inventario = ?`,
            [original.inv_original]
          );
        }
      }
    }

    await conn.commit();
    res.redirect('/salidas');
  } catch (err) {
    await conn.rollback();
    console.error('Error editando salida (delta):', err);
    res.send('Error editando salida');
  } finally {
    conn.release();
  }
});


/* ===== Inventario ===== */
app.get('/inventario', estaLogueado, async (req, res) => {
  try {
    const [inventario] = await db.query(`
      SELECT
        i.id_inventario,
        i.producto_FKinventario,
        i.lote_inventario,
        i.stock_inventario,
        i.caducidad_inventario,
        i.estadoDelProducto_inventario,
        i.id_cliente_propietario,
        DATEDIFF(i.caducidad_inventario, CURDATE()) AS DiasRestantes,
        CONCAT('(', c.clave_catalogo, ') ', c.nombreProdu_catalogo) AS ProductoNombre,
        cli.nombre_cliente AS PropietarioNombre
      FROM inventario i
      LEFT JOIN catalogo c
        ON i.producto_FKinventario = c.id_catalogo
      LEFT JOIN cliente cli
        ON i.id_cliente_propietario = cli.id_cliente
      ORDER BY c.nombreProdu_catalogo ASC, i.caducidad_inventario ASC
    `);

    res.render('inventario', {
      inventario,
      usuario: req.session.usuario
    });

  } catch (err) {
    console.error(err);
    res.send('Error cargando inventario');
  }
});


/* ===== Clientes ===== */
app.get('/clientes', estaLogueado, async (req, res) => {
  try {
    const [resultados] = await db.query(`
      SELECT
        id_cliente        AS Id,
        nombre_cliente    AS Nombre,
        RFC_cliente       AS RFC,
        direccion_cliente AS Direccion,
        telefono_cliente  AS Telefono,
        correo_cliente    AS Correo,
        es_3pl            AS Es3PL
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    res.render('clientes', {
      clientes: resultados,
      usuario: req.session.usuario
    });

  } catch (err) {
    console.error(err);
    res.send('Error cargando clientes');
  }
});

/* ===== Exportar Clientes a Excel ===== */
app.get('/clientes/exportar', estaLogueado, async (req, res) => {
  try {
    const [clientes] = await db.query(`
      SELECT
        nombre_cliente    AS Nombre,
        RFC_cliente       AS RFC,
        direccion_cliente AS Direccion,
        telefono_cliente  AS Telefono,
        correo_cliente    AS Correo,
        es_3pl            AS Es3PL
      FROM cliente
      ORDER BY nombre_cliente ASC
    `);

    const ExcelJS = require('exceljs');
    const workbook = new ExcelJS.Workbook();
    const ws = workbook.addWorksheet('Clientes');

    ws.columns = [
      { header: 'Nombre',    key: 'Nombre',   width: 40 },
      { header: 'RFC',       key: 'RFC',      width: 20 },
      { header: 'Dirección', key: 'Direccion',width: 50 },
      { header: 'Teléfono',  key: 'Telefono', width: 20 },
      { header: 'Correo',    key: 'Correo',   width: 35 },
      { header: 'Es 3PL',    key: 'Es3PL',    width: 10 },
    ];

    clientes.forEach(c => ws.addRow(c));
    ws.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=clientes.xlsx'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando clientes:', err);
    res.send('Error exportando clientes');
  }
});

/* ===== Nuevo Cliente ===== */
app.get('/clientes/nuevo', estaLogueado, puedeEditarClientes, async (req, res) => {
  const cliente = {
    Id: 0,
    Nombre: '',
    RFC: '',
    Direccion: '',
    Telefono: '',
    Correo: '',
    Es3PL: 0
  };
  res.render('editar_cliente', {
    editar: false,
    cliente,
    usuario: req.session.usuario
  });
});

function parseEs3pl(value) {
  if (!value) return 0;
  const v = String(value).toLowerCase();
  return (v === 'on' || v === '1' || v === 'true') ? 1 : 0;
}

/* ===== Nuevo Cliente ===== */
app.post('/clientes/nuevo', estaLogueado, puedeEditarClientes, async (req, res) => {
  const { Nombre, RFC, Direccion, Telefono, Correo, es_3pl } = req.body;
  const es3pl = parseEs3pl(es_3pl);

  try {
    await db.query(
      `INSERT INTO cliente
        (nombre_cliente, RFC_cliente, direccion_cliente, telefono_cliente, correo_cliente, es_3pl)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [Nombre, RFC, Direccion, Telefono, Correo, es3pl]
    );
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error al agregar cliente:', err);
    res.send('Error al agregar cliente');
  }
});

/* ===== Editar Cliente ===== */
app.get('/clientes/editar/:id', estaLogueado, puedeEditarClientes, async (req, res) => {
  const clienteId = req.params.id;
  try {
    const [resultados] = await db.query(`
      SELECT
        id_cliente        AS Id,
        nombre_cliente    AS Nombre,
        RFC_cliente       AS RFC,
        direccion_cliente AS Direccion,
        telefono_cliente  AS Telefono,
        correo_cliente    AS Correo,
        es_3pl            AS Es3PL
      FROM cliente
      WHERE id_cliente = ?
    `, [clienteId]);

    if (resultados.length === 0) {
      return res.send('Cliente no encontrado');
    }

    res.render('editar_cliente', {
      editar: true,
      cliente: resultados[0],
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error al cargar cliente:', err);
    res.send('Error al cargar cliente');
  }
});

/* ===== Editar Cliente ===== */
app.post('/clientes/editar/:id', estaLogueado, puedeEditarClientes, async (req, res) => {
  const clienteId = req.params.id;
  const { Nombre, RFC, Direccion, Telefono, Correo, es_3pl } = req.body;
  const es3pl = parseEs3pl(es_3pl);

  try {
    await db.query(
      `UPDATE cliente
         SET nombre_cliente    = ?,
             RFC_cliente       = ?,
             direccion_cliente = ?,
             telefono_cliente  = ?,
             correo_cliente    = ?,
             es_3pl            = ?
       WHERE id_cliente = ?`,
      [Nombre, RFC, Direccion, Telefono, Correo, es3pl, clienteId]
    );
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error al actualizar cliente:', err);
    res.send('Error al actualizar cliente');
  }
});
/* ===== Eliminar Cliente ===== */
app.post('/clientes/eliminar/:id', estaLogueado, puedeEditarClientes, async (req, res) => {
  const clienteId = req.params.id;
  try {
    await db.query('DELETE FROM cliente WHERE id_cliente = ?', [clienteId]);
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error eliminando cliente:', err);
    res.send('Error al eliminar cliente');
  }
});


/* ===== Cotizaciones ===== */
function formatDateLocal(date) {
  if (!date) return null;
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}
function parseDateLocal(s) {
  if (!s) return null;
  const [y, m, d] = String(s).split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) return null;
  return dt;
}
function addDaysLocal(dt, days) {
  const c = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate());
  c.setDate(c.getDate() + days);
  return c;
}
function diffDaysLocal(a, b) {
  const MS = 86400000;
  const a0 = new Date(a.getFullYear(), a.getMonth(), a.getDate());
  const b0 = new Date(b.getFullYear(), b.getMonth(), b.getDate());
  return Math.round((b0 - a0) / MS);
}
function calcularVigenciaYFechaFin(fechaDeFolio, vigenciaInput, fechaFinInput) {
  const inicio = parseDateLocal(fechaDeFolio);
  if (!inicio) return { vigencia: null, fechaFin: null };
  const vStr = (vigenciaInput ?? '').toString().trim();
  const fStr = (fechaFinInput ?? '').toString().trim();
  let vigencia = (vStr !== '' && !Number.isNaN(Number(vStr))) ? Number(vStr) : null;
  let fechaFin = fStr !== '' ? parseDateLocal(fStr) : null;
  if (vigencia !== null && vigencia >= 0 && !fechaFin) {
    fechaFin = addDaysLocal(inicio, vigencia);
  } else if ((vigencia === null || Number.isNaN(vigencia)) && fechaFin) {
    const dias = diffDaysLocal(inicio, fechaFin);
    vigencia = dias >= 0 ? dias : null;
  } else if (vigencia !== null && fechaFin) {
    fechaFin = addDaysLocal(inicio, Math.max(0, vigencia));
  } else {
    return { vigencia: null, fechaFin: null };
  }
  if (vigencia !== null && (!Number.isFinite(vigencia) || vigencia < 0)) vigencia = null;
  const fechaFinStr = fechaFin ? formatDateLocal(fechaFin) : null;
  return { vigencia, fechaFin: fechaFinStr };
}

async function getConsecutivoCotizacionId(conn) {
  const [r] = await conn.query('SELECT id_consecutivo FROM consecutivo WHERE nombre=? LIMIT 1', ['cotizacion']);
  if (r.length) return r[0].id_consecutivo;
  const [ins] = await conn.query('INSERT INTO consecutivo (nombre, ultimoValor) VALUES (?,?)', ['cotizacion', 0]);
  return ins.insertId;
}

async function generateFolioIfEmpty(conn, folioInput) {
  const folio = (folioInput ?? '').trim();
  if (folio !== '') return folio;
  const [cur] = await conn.query('SELECT id_consecutivo, ultimoValor FROM consecutivo WHERE nombre=? FOR UPDATE', ['cotizacion']);
  let idc, ultimo = 0;
  if (cur.length) {
    idc = cur[0].id_consecutivo;
    ultimo = Number(cur[0].ultimoValor || 0);
  } else {
    const [ins] = await conn.query('INSERT INTO consecutivo (nombre, ultimoValor) VALUES (?,?)', ['cotizacion', 0]);
    idc = ins.insertId; ultimo = 0;
  }
  const siguiente = ultimo + 1;
  await conn.query('UPDATE consecutivo SET ultimoValor=? WHERE id_consecutivo=?', [siguiente, idc]);
  return `SLM-${String(siguiente).padStart(4, '0')}`;
}

app.get('/cotizaciones', estaLogueado, async (req, res) => {
  try {
    // ========= 1) Leer filtros desde query =========
    const qRaw = (req.query.q || '').toString().trim();
    const mesRaw = (req.query.mes || '').toString().trim();
    const anioRaw = (req.query.anio || '').toString().trim();
    const dependenciaRaw = (req.query.dependencia || '').toString().trim();
    const responsableRaw = (req.query.responsable || '').toString().trim(); // id_usuario
    const estatusRaw = (req.query.estatus || '').toString().trim();     // 'aprobada','rechazada','pendiente'

    let q = qRaw;
    let mes = mesRaw ? parseInt(mesRaw, 10) : null;
    let anio = anioRaw ? parseInt(anioRaw, 10) : null;
    let dependencia = dependenciaRaw || '';
    let responsable = responsableRaw || '';
    let estatus = estatusRaw || '';

    if (isNaN(mes)) mes = null;
    if (isNaN(anio)) anio = null;

    // Mapeo de estatus del filtro (minúsculas) a lo que guardas en BD
    const mapaEstatus = {
      'aprobada': 'Aprobada',
      'rechazada': 'Rechazada',
      'pendiente': 'Pendiente'
    };
    const estatusBD = estatus ? (mapaEstatus[estatus.toLowerCase()] || null) : null;

    // ========= 2) WHERE dinámico =========
    const condiciones = [];
    const params = [];

    if (mes !== null) {
      condiciones.push('MONTH(c.fechaDeFolio_cotizacion) = ?');
      params.push(mes);
    }

    if (anio !== null) {
      condiciones.push('YEAR(c.fechaDeFolio_cotizacion) = ?');
      params.push(anio);
    }

    if (dependencia !== '') {
      condiciones.push('c.dependencia_cotizacion = ?');
      params.push(dependencia);
    }

    if (responsable !== '') {
      condiciones.push('c.responsableDeLaCotizacionFK = ?');
      params.push(parseInt(responsable, 10));
    }

    if (estatusBD) {
      condiciones.push('c.estatus_cotizacion = ?');
      params.push(estatusBD);
    }

    if (q !== '') {
      const like = `%${q}%`;
      condiciones.push(`
        (
          c.folio_cotizacion LIKE ?               -- folio manual
          OR CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0')) LIKE ? -- folio autogenerado
          OR c.dependencia_cotizacion LIKE ?
          OR COALESCE(u.nombreCompleto, '') LIKE ?
          OR c.estatus_cotizacion LIKE ?
        )
      `);
      for (let i = 0; i < 5; i++) params.push(like);
    }

    const whereClause = condiciones.length
      ? 'WHERE ' + condiciones.join(' AND ')
      : '';

    // ========= 3) Consulta principal =========
    const [cotizaciones] = await db.query(`
      SELECT
        c.id_cotizacion AS id,
        CASE
          WHEN c.folio_cotizacion IS NOT NULL AND c.folio_cotizacion <> ''
            THEN c.folio_cotizacion
          ELSE CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0'))
        END AS folioVisible,
        c.noDeFolio_FKcotizacion       AS noDeFolioFK,
        c.fechaDeFolio_cotizacion      AS fechaDeFolio,
        c.partidasCotizadas_cotizacion AS partidasCotizadas,
        c.montoMaxCotizado_cotizacion  AS montoMaxCotizado,
        c.dependencia_cotizacion       AS dependencia,
        c.vigenciaDeLaCotizacion       AS vigenciaDeLaCotizacion,
        c.fechaFinDeLaCotizacion       AS fechaFinDeLaCotizacion,
        COALESCE(u.nombreCompleto, '—') AS responsableDeLaCotizacion,
        c.responsableDeLaCotizacionFK  AS responsableDeLaCotizacionFK,
        c.estatus_cotizacion           AS estatusDeLaCotizacion,
        c.partidasAsignadas_cotizacion AS partidasAsignadas,
        c.montoMaxAsignado_cotizacion  AS montoMaximoAsignado
      FROM cotizacion c
      LEFT JOIN usuario u ON u.id_usuario = c.responsableDeLaCotizacionFK
      ${whereClause}
      ORDER BY folioVisible DESC   -- 👈 ahora de mayor folio a menor
    `, params);

    // ========= 4) Adjuntos por cotización =========
    let adjuntosPorCotizacion = {};

    if (cotizaciones.length > 0) {
      const ids = cotizaciones.map(c => c.id);

      const [adjuntos] = await db.query(
        `
          SELECT 
            id_archivo,
            id_registro,
            nombre_original
          FROM archivo_adjunto
          WHERE modulo = 'cotizacion'
            AND id_registro IN (?)
        `,
        [ids]
      );

      adjuntos.forEach(a => {
        if (!adjuntosPorCotizacion[a.id_registro]) {
          adjuntosPorCotizacion[a.id_registro] = [];
        }
        adjuntosPorCotizacion[a.id_registro].push(a);
      });
    }

    // ========= 5) Listas para filtros =========

    const [periodos] = await db.query(`
      SELECT DISTINCT
        YEAR(c.fechaDeFolio_cotizacion)  AS anio,
        MONTH(c.fechaDeFolio_cotizacion) AS mes
      FROM cotizacion c
      WHERE c.fechaDeFolio_cotizacion IS NOT NULL
      ORDER BY anio DESC, mes ASC
    `);

    const setAnios = new Set();
    const setMeses = new Set();

    periodos.forEach(p => {
      if (p.anio) setAnios.add(p.anio);
      if (p.mes) setMeses.add(p.mes);
    });

    const listaAniosCot = Array.from(setAnios).sort((a, b) => b - a); // años desc
    const listaMesesCot = Array.from(setMeses).sort((a, b) => a - b); // meses asc

    const [depsRows] = await db.query(`
      SELECT DISTINCT dependencia_cotizacion AS dependencia
      FROM cotizacion
      WHERE dependencia_cotizacion IS NOT NULL
        AND dependencia_cotizacion <> ''
      ORDER BY dependencia_cotizacion ASC
    `);
    const dependenciasLista = depsRows.map(r => r.dependencia);

    const [respRows] = await db.query(`
      SELECT DISTINCT
        u.id_usuario,
        u.nombreCompleto
      FROM cotizacion c
      JOIN usuario u ON u.id_usuario = c.responsableDeLaCotizacionFK
      WHERE c.responsableDeLaCotizacionFK IS NOT NULL
      ORDER BY u.nombreCompleto ASC
    `);
    const responsablesLista = respRows;

    res.render('cotizaciones', {
      usuario: req.session.usuario,
      cotizaciones,
      adjuntosPorCotizacion,
      q,
      mes,
      anio,
      dependencia,
      responsable,
      estatus,
      listaAniosCot,
      listaMesesCot,
      dependenciasLista,
      responsablesLista
    });
  } catch (err) {
    console.error('Error cargando cotizaciones:', err);
    res.status(500).send('Error en el servidor');
  }
});

app.get('/cotizaciones/exportar', estaLogueado, async (req, res) => {
  try {
    // ========= 1) Leer mismos filtros que /cotizaciones =========
    const qRaw = (req.query.q || '').toString().trim();
    const mesRaw = (req.query.mes || '').toString().trim();
    const anioRaw = (req.query.anio || '').toString().trim();
    const dependenciaRaw = (req.query.dependencia || '').toString().trim();
    const responsableRaw = (req.query.responsable || '').toString().trim(); // id_usuario
    const estatusRaw = (req.query.estatus || '').toString().trim();     // 'aprobada','rechazada','pendiente'

    let q = qRaw;
    let mes = mesRaw ? parseInt(mesRaw, 10) : null;
    let anio = anioRaw ? parseInt(anioRaw, 10) : null;
    let dependencia = dependenciaRaw || '';
    let responsable = responsableRaw || '';
    let estatus = estatusRaw || '';

    if (isNaN(mes)) mes = null;
    if (isNaN(anio)) anio = null;

    const mapaEstatus = {
      'aprobada': 'Aprobada',
      'rechazada': 'Rechazada',
      'pendiente': 'Pendiente'
    };
    const estatusBD = estatus ? (mapaEstatus[estatus.toLowerCase()] || null) : null;

    const condiciones = [];
    const params = [];

    if (mes !== null) {
      condiciones.push('MONTH(c.fechaDeFolio_cotizacion) = ?');
      params.push(mes);
    }

    if (anio !== null) {
      condiciones.push('YEAR(c.fechaDeFolio_cotizacion) = ?');
      params.push(anio);
    }

    if (dependencia !== '') {
      condiciones.push('c.dependencia_cotizacion = ?');
      params.push(dependencia);
    }

    if (responsable !== '') {
      condiciones.push('c.responsableDeLaCotizacionFK = ?');
      params.push(parseInt(responsable, 10));
    }

    if (estatusBD) {
      condiciones.push('c.estatus_cotizacion = ?');
      params.push(estatusBD);
    }

    if (q !== '') {
      const like = `%${q}%`;
      condiciones.push(`
        (
          c.folio_cotizacion LIKE ?
          OR CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0')) LIKE ?
          OR c.dependencia_cotizacion LIKE ?
          OR COALESCE(u.nombreCompleto, '') LIKE ?
          OR c.estatus_cotizacion LIKE ?
        )
      `);
      for (let i = 0; i < 5; i++) params.push(like);
    }

    const whereClause = condiciones.length
      ? 'WHERE ' + condiciones.join(' AND ')
      : '';

    const [rows] = await db.query(`
      SELECT
        c.id_cotizacion AS id,
        CASE
          WHEN c.folio_cotizacion IS NOT NULL AND c.folio_cotizacion <> ''
            THEN c.folio_cotizacion
          ELSE CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0'))
        END AS folioVisible,
        c.noDeFolio_FKcotizacion       AS noDeFolioFK,
        c.fechaDeFolio_cotizacion      AS fechaDeFolio,
        c.partidasCotizadas_cotizacion AS partidasCotizadas,
        c.montoMaxCotizado_cotizacion  AS montoMaxCotizado,
        c.dependencia_cotizacion       AS dependencia,
        c.vigenciaDeLaCotizacion       AS vigenciaDeLaCotizacion,
        c.fechaFinDeLaCotizacion       AS fechaFinDeLaCotizacion,
        COALESCE(u.nombreCompleto, '—') AS responsableDeLaCotizacion,
        c.estatus_cotizacion           AS estatusDeLaCotizacion,
        c.partidasAsignadas_cotizacion AS partidasAsignadas,
        c.montoMaxAsignado_cotizacion  AS montoMaximoAsignado
      FROM cotizacion c
      LEFT JOIN usuario u ON u.id_usuario = c.responsableDeLaCotizacionFK
      ${whereClause}
      ORDER BY folioVisible DESC
    `, params);

    // ========= 2) Crear Excel =========
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Cotizaciones');

    worksheet.columns = [
      { header: 'Folio', key: 'folioVisible', width: 15 },
      { header: 'No. Folio (consecutivo)', key: 'noDeFolioFK', width: 20 },
      { header: 'Fecha de folio', key: 'fechaDeFolio', width: 15 },
      { header: 'Partidas cotizadas', key: 'partidasCotizadas', width: 18 },
      { header: 'Monto máx. cotizado', key: 'montoMaxCotizado', width: 20 },
      { header: 'Dependencia', key: 'dependencia', width: 30 },
      { header: 'Vigencia (días)', key: 'vigenciaDeLaCotizacion', width: 16 },
      { header: 'Fecha fin', key: 'fechaFinDeLaCotizacion', width: 15 },
      { header: 'Responsable', key: 'responsableDeLaCotizacion', width: 30 },
      { header: 'Estatus', key: 'estatusDeLaCotizacion', width: 15 },
      { header: 'Partidas asignadas', key: 'partidasAsignadas', width: 18 },
      { header: 'Monto máx. asignado', key: 'montoMaximoAsignado', width: 20 }
    ];

    rows.forEach(r => {
      worksheet.addRow({
        folioVisible: r.folioVisible || '',
        noDeFolioFK: r.noDeFolioFK || '',
        fechaDeFolio: r.fechaDeFolio ? new Date(r.fechaDeFolio).toLocaleDateString('es-MX') : '',
        partidasCotizadas: r.partidasCotizadas || 0,
        montoMaxCotizado: r.montoMaxCotizado || 0,
        dependencia: r.dependencia || '',
        vigenciaDeLaCotizacion: r.vigenciaDeLaCotizacion != null ? r.vigenciaDeLaCotizacion : '',
        fechaFinDeLaCotizacion: r.fechaFinDeLaCotizacion ? new Date(r.fechaFinDeLaCotizacion).toLocaleDateString('es-MX') : '',
        responsableDeLaCotizacion: r.responsableDeLaCotizacion || '',
        estatusDeLaCotizacion: r.estatusDeLaCotizacion || '',
        partidasAsignadas: r.partidasAsignadas || 0,
        montoMaximoAsignado: r.montoMaximoAsignado || 0
      });
    });

    // Encabezados de respuesta
    res.setHeader('Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="cotizaciones.xlsx"'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando cotizaciones a Excel:', err);
    res.status(500).send('Error al exportar cotizaciones');
  }
});

app.get('/cotizaciones/buscar', estaLogueado, async (req, res) => {
  const folio = req.query.folio_buscar?.toString().trim();
  if (!folio) return res.redirect('/cotizaciones');

  try {
    const isNumeric = /^\d+$/.test(folio);

    const [cotizaciones] = await db.query(`
      SELECT
        c.id_cotizacion AS id,
        CASE
          WHEN c.folio_cotizacion IS NOT NULL AND c.folio_cotizacion <> ''
            THEN c.folio_cotizacion
          ELSE CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0'))
        END AS folioVisible,
        c.noDeFolio_FKcotizacion       AS noDeFolioFK,
        c.fechaDeFolio_cotizacion      AS fechaDeFolio,
        c.partidasCotizadas_cotizacion AS partidasCotizadas,
        c.montoMaxCotizado_cotizacion  AS montoMaxCotizado,
        c.dependencia_cotizacion       AS dependencia,
        c.vigenciaDeLaCotizacion       AS vigenciaDeLaCotizacion,
        c.fechaFinDeLaCotizacion       AS fechaFinDeLaCotizacion,
        COALESCE(u.nombreCompleto, '—') AS responsableDeLaCotizacion,
        c.estatus_cotizacion           AS estatusDeLaCotizacion,
        c.partidasAsignadas_cotizacion AS partidasAsignadas,
        c.montoMaxAsignado_cotizacion  AS montoMaximoAsignado
      FROM cotizacion c
      LEFT JOIN usuario u ON u.id_usuario = c.responsableDeLaCotizacionFK
      WHERE
        (c.folio_cotizacion IS NOT NULL AND c.folio_cotizacion <> '' AND c.folio_cotizacion = ?)
        OR (CONCAT('SLM-', LPAD(c.id_cotizacion, 5, '0')) = ?)
        OR (c.id_cotizacion = ?)
      ORDER BY c.id_cotizacion DESC
    `, [
      folio,
      folio,
      isNumeric ? Number(folio) : -1
    ]);

    res.render('cotizaciones', { cotizaciones, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error buscando cotización por folio:', err);
    res.send('Error buscando cotización por folio');
  }
});

app.get('/cotizaciones/nueva', estaLogueado, puedeEditarCotizaciones, async (req, res) => {
  try {
    const [usuarios] = await db.query(
      'SELECT id_usuario, nombreCompleto AS nombre_usuario FROM usuario ORDER BY nombreCompleto ASC'
    );
    res.render('editar_cotizaciones', { cotizacion: null, usuario: req.session.usuario, usuarios });
  } catch (err) {
    console.error('Error cargando usuarios:', err);
    res.status(500).send('Error al cargar formulario de cotización');
  }
});

app.post('/cotizaciones/nueva', estaLogueado, puedeEditarCotizaciones, async (req, res) => {
  let conn;
  try {
    const {
      folioVisible, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia,
      vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, estatusDeLaCotizacion,
      partidasAsignadas, montoMaximoAsignado, responsableDeLaCotizacion
    } = req.body;

    if (!fechaDeFolio) throw new Error('Fecha de Folio requerida.');

    const { vigencia, fechaFin } = calcularVigenciaYFechaFin(
      fechaDeFolio, vigenciaDeLaCotizacion, fechaFinDeLaCotizacion
    );

    conn = await db.getConnection();
    await conn.beginTransaction();

    const idConsecutivo = await getConsecutivoCotizacionId(conn);
    const folioParaGuardar = await generateFolioIfEmpty(conn, folioVisible);

    await conn.query(
      `INSERT INTO cotizacion
       (noDeFolio_FKcotizacion, folio_cotizacion, fechaDeFolio_cotizacion,
        partidasCotizadas_cotizacion, montoMaxCotizado_cotizacion, dependencia_cotizacion,
        vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, responsableDeLaCotizacionFK,
        estatus_cotizacion, partidasAsignadas_cotizacion, montoMaxAsignado_cotizacion)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        idConsecutivo, folioParaGuardar, fechaDeFolio,
        Number(partidasCotizadas || 0), Number(montoMaxCotizado || 0),
        (dependencia ?? '').trim() || null, vigencia, fechaFin,
        Number(responsableDeLaCotizacion) || null,
        (estatusDeLaCotizacion || 'pendiente'),
        Number(partidasAsignadas || 0), Number(montoMaximoAsignado || 0),
      ]
    );

    await conn.commit();
    res.redirect('/cotizaciones');
  } catch (err) {
    if (conn) await conn.rollback();
    console.error('Error guardando cotización:', err.code || '', err.sqlMessage || err.message);
    res.status(500).send('Error al guardar la cotización');
  } finally {
    if (conn) conn.release();
  }
});

app.get('/cotizaciones/editar/:id', estaLogueado, puedeEditarCotizaciones, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await db.query(
      `SELECT
         c.id_cotizacion                AS id,
         c.noDeFolio_FKcotizacion       As noDeFolioFK,
         c.folio_cotizacion             AS folioVisible,
         c.fechaDeFolio_cotizacion      AS fechaDeFolio,
         c.partidasCotizadas_cotizacion AS partidasCotizadas,
         c.montoMaxCotizado_cotizacion  AS montoMaxCotizado,
         c.dependencia_cotizacion       AS dependencia,
         c.vigenciaDeLaCotizacion       AS vigenciaDeLaCotizacion,
         c.fechaFinDeLaCotizacion       AS fechaFinDeLaCotizacion,
         c.responsableDeLaCotizacionFK  AS responsableDeLaCotizacion,
         c.estatus_cotizacion           AS estatusDeLaCotizacion,
         c.partidasAsignadas_cotizacion AS partidasAsignadas,
         c.montoMaxAsignado_cotizacion  AS montoMaximoAsignado
       FROM cotizacion c
       WHERE c.id_cotizacion = ?`,
      [id]
    );

    if (!rows.length) return res.status(404).send('Cotización no encontrada');

    const c = rows[0];
    const formatYMD = d => {
      if (!d) return '';
      const dt = new Date(d);
      const y = dt.getFullYear();
      const m = String(dt.getMonth() + 1).padStart(2, '0');
      const dd = String(dt.getDate()).padStart(2, '0');
      return `${y}-${m}-${dd}`;
    };
    c.fechaDeFolioYmd = formatYMD(c.fechaDeFolio);
    c.fechaFinDeLaCotizacionYmd = formatYMD(c.fechaFinDeLaCotizacion);

    const [usuarios] = await db.query(
      'SELECT id_usuario, nombreCompleto AS nombre_usuario FROM usuario ORDER BY nombreCompleto ASC'
    );

    res.render('editar_cotizaciones', { cotizacion: c, usuarios, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando cotización:', err);
    res.status(500).send('Error en el servidor');
  }
});

app.post('/cotizaciones/editar/:id', estaLogueado, puedeEditarCotizaciones, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const toNumOrNull = v => (v === undefined || v === null || String(v).trim() === '') ? null : Number(v);
    const trimOrNull = v => { const s = (v ?? '').trim(); return s === '' ? null : s; };

    const {
      folioVisible, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia,
      vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, estatusDeLaCotizacion,
      partidasAsignadas, montoMaximoAsignado, responsableDeLaCotizacion
    } = req.body;

    const { vigencia, fechaFin } = calcularVigenciaYFechaFin(
      fechaDeFolio, vigenciaDeLaCotizacion, fechaFinDeLaCotizacion
    );

    const folioParaGuardar = trimOrNull(folioVisible);
    const fechaDeFolioSQL = fechaDeFolio || null;
    const partidasCotizadasSQL = toNumOrNull(partidasCotizadas);
    const partidasAsignadasSQL = toNumOrNull(partidasAsignadas);
    const montoMaxCotizadoSQL = toNumOrNull(montoMaxCotizado);
    const montoMaximoAsignadoSQL = toNumOrNull(montoMaximoAsignado);
    const dependenciaSQL = trimOrNull(dependencia);
    const responsableFKSQL = toNumOrNull(responsableDeLaCotizacion);
    const estatusSQL = estatusDeLaCotizacion || 'pendiente';

    conn = await db.getConnection();
    await conn.beginTransaction();

    await conn.query(
      `UPDATE cotizacion SET
      folio_cotizacion             = ?,
      fechaDeFolio_cotizacion      = ?,
      partidasCotizadas_cotizacion = ?,
      montoMaxCotizado_cotizacion  = ?,
      dependencia_cotizacion       = ?,
      vigenciaDeLaCotizacion       = ?,
      fechaFinDeLaCotizacion       = ?,
      responsableDeLaCotizacionFK  = ?,
      estatus_cotizacion           = ?,
      partidasAsignadas_cotizacion = ?,
      montoMaxAsignado_cotizacion  = ?
      WHERE id_cotizacion = ?`,
      [
        folioParaGuardar,
        fechaDeFolioSQL,
        partidasCotizadasSQL,
        montoMaxCotizadoSQL,
        dependenciaSQL,
        vigencia,
        fechaFin,
        responsableFKSQL,
        estatusSQL,
        partidasAsignadasSQL,
        montoMaximoAsignadoSQL,
        id
      ]
    );

    await conn.commit();
    res.redirect('/cotizaciones');
  } catch (err) {
    if (conn) await conn.rollback();
    console.error('Error actualizando cotización:', err.code || '', err.sqlMessage || err.message);
    res.status(500).send('Error al actualizar la cotización');
  } finally {
    if (conn) conn.release();
  }
});

app.get('/cotizaciones/eliminar/:id', estaLogueado, puedeEditarCotizaciones, async (req, res) => {
  try {
    await db.query('DELETE FROM cotizacion WHERE id_cotizacion = ?', [req.params.id]);
  } catch (err) {
    console.error('Error eliminando cotización:', err);
  } finally {
    res.redirect('/cotizaciones');
  }
});


// ===============================FACTURACION===============================

// ===== Middleware para restringir a administradores y facturación =====
function soloAdminYFacturacion(req, res, next) {
  if (!req.session?.usuario) {
    return res.redirect('/acceso');
  }
  const tipo = getTipoUsuario(req);
  if (tipo === 'administrador' || tipo === 'facturacion') {
    return next();
  }
  return res.status(403).send('No tienes permisos para ver el módulo de facturación.');
}

/* ===== Rutas de Facturación ===== */
// Listado + buscador flexible + barra lateral mes/año + total del mes
app.get('/facturacion', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    const hoy = new Date();

    const q = (req.query.q || '').trim();
    const filtroEstado = (req.query.estado || '').trim();
    const mesRaw = req.query.mes;
    const anioRaw = req.query.anio;

    let mes = null;
    let anio = null;
    let usarFiltroFecha = false;

    if (mesRaw) {
      const m = parseInt(mesRaw, 10);
      if (!isNaN(m) && m >= 1 && m <= 12) {
        mes = m;
        usarFiltroFecha = true;
      }
    }

    if (anioRaw) {
      const a = parseInt(anioRaw, 10);
      if (!isNaN(a) && a >= 2000) {
        anio = a;
        usarFiltroFecha = true;
      }
    }

    // Si no hay nada, por defecto mes/año actual
    if (!q && !filtroEstado && !usarFiltroFecha) {
      mes = hoy.getMonth() + 1;
      anio = hoy.getFullYear();
      usarFiltroFecha = true;
    }

    const condiciones = [];
    const params = [];

    if (usarFiltroFecha && mes && anio) {
      condiciones.push('MONTH(f.fecha) = ?');
      params.push(mes);

      condiciones.push('YEAR(f.fecha) = ?');
      params.push(anio);
    }

    if (filtroEstado && ['pagado', 'pendiente', 'cancelado'].includes(filtroEstado)) {
      condiciones.push('f.estado = ?');
      params.push(filtroEstado);
    }

    if (q) {
      const like = `%${q}%`;
      condiciones.push(`
        (
          f.odc LIKE ? OR
          f.folio_fiscal LIKE ? OR
          f.factura LIKE ? OR
          cli.nombre_cliente LIKE ? OR
          cli.RFC_cliente LIKE ? OR
          cat.clave_catalogo LIKE ? OR
          cat.claveSSA_catalogo LIKE ? OR
          cat.nombreProdu_catalogo LIKE ?
        )
      `);
      for (let i = 0; i < 8; i++) params.push(like);
    }

    const whereClause = condiciones.length ? 'WHERE ' + condiciones.join(' AND ') : '';

    const [facturas] = await db.query(`
      SELECT
        f.*,
        cat.clave_catalogo,
        cat.claveSSA_catalogo,
        cat.nombreProdu_catalogo,
        cli.nombre_cliente,
        cli.RFC_cliente,
        u.nombreCompleto AS nombre_usuario
      FROM facturacion f
      LEFT JOIN catalogo cat ON f.producto_fk = cat.id_catalogo
      LEFT JOIN cliente cli ON f.cliente_fk = cli.id_cliente
      LEFT JOIN usuario u ON f.usuario_fk = u.id_usuario
      ${whereClause}
      ORDER BY
        f.serie_factura ASC,
        f.numero_factura ASC
    `, params);

    // Adjuntos
    const [adjRows] = await db.query(`
      SELECT id_archivo, id_registro, nombre_original
      FROM archivo_adjunto
      WHERE modulo = 'facturacion'
    `);

    const adjuntosPorFactura = {};
    for (const row of adjRows) {
      if (!adjuntosPorFactura[row.id_registro]) {
        adjuntosPorFactura[row.id_registro] = [];
      }
      adjuntosPorFactura[row.id_registro].push(row);
    }

    // Total del mes
    let totalMes = 0;
    if (usarFiltroFecha && mes && anio) {
      const [[rowTotal]] = await db.query(`
        SELECT SUM(monto) AS total
        FROM facturacion
        WHERE MONTH(fecha) = ? AND YEAR(fecha) = ?
      `, [mes, anio]);

      totalMes = rowTotal && rowTotal.total ? rowTotal.total : 0;
    }

    // Periodos para barra lateral
    const [periodos] = await db.query(`
      SELECT DISTINCT YEAR(fecha) AS anio, MONTH(fecha) AS mes
      FROM facturacion
      ORDER BY anio DESC, mes DESC
    `);

    const periodosPorAnio = {};
    const listaAnios = [];

    for (const fila of periodos) {
      if (!periodosPorAnio[fila.anio]) {
        periodosPorAnio[fila.anio] = [];
        listaAnios.push(fila.anio);
      }
      periodosPorAnio[fila.anio].push(fila.mes);
    }

    // Guardar filtros actuales en sesión
    req.session.filtrosFacturacion = {
      mes,
      anio,
      estado: filtroEstado,
      q
    };

    res.render('facturacion', {
      usuario: req.session.usuario,
      facturas,
      adjuntosPorFactura,
      mesActual: mes,
      anioActual: anio,
      periodosPorAnio,
      listaAnios,
      totalMes,
      q,
      filtroEstado,
      ruta: 'facturacion'
    });
  } catch (err) {
    console.error('Error cargando facturación:', err);
    res.send('Error cargando facturación');
  }
});

app.get('/facturacion/exportar', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    const hoy = new Date();

    const q = (req.query.q || '').trim();
    const filtroEstado = (req.query.estado || '').trim();
    const anioRaw = req.query.anio;

    // Año a exportar: si no viene, usamos el año actual
    let anio = anioRaw ? parseInt(anioRaw, 10) : hoy.getFullYear();
    if (isNaN(anio) || anio < 2000) {
      anio = hoy.getFullYear();
    }

    const condiciones = [];
    const params = [];

    // SIEMPRE por año (para poder separar por meses en el Excel)
    condiciones.push('YEAR(f.fecha) = ?');
    params.push(anio);

    if (filtroEstado && ['pagado', 'pendiente', 'cancelado'].includes(filtroEstado)) {
      condiciones.push('f.estado = ?');
      params.push(filtroEstado);
    }

    if (q) {
      const like = `%${q}%`;
      condiciones.push(`
        (
          f.odc LIKE ?
          OR f.folio_fiscal LIKE ?
          OR f.factura LIKE ?
          OR cli.nombre_cliente LIKE ?
          OR cli.RFC_cliente LIKE ?
          OR cat.clave_catalogo LIKE ?
          OR cat.claveSSA_catalogo LIKE ?
          OR cat.nombreProdu_catalogo LIKE ?
        )
      `);
      for (let i = 0; i < 8; i++) params.push(like);
    }

    const whereClause = condiciones.length ? 'WHERE ' + condiciones.join(' AND ') : '';

    // Traemos todas las facturas de ese año (y demás filtros) y calculamos el mes en la consulta
    const [rows] = await db.query(`
      SELECT
        f.*,
        cat.clave_catalogo,
        cat.claveSSA_catalogo,
        cat.nombreProdu_catalogo,
        cli.nombre_cliente,
        cli.RFC_cliente,
        u.nombreCompleto AS nombre_usuario,
        MONTH(f.fecha) AS mes_num
      FROM facturacion f
      LEFT JOIN catalogo cat ON f.producto_fk = cat.id_catalogo
      LEFT JOIN cliente cli ON f.cliente_fk = cli.id_cliente
      LEFT JOIN usuario u   ON f.usuario_fk  = u.id_usuario
      ${whereClause}
      ORDER BY
        f.fecha ASC,
        f.serie_factura ASC,
        f.numero_factura ASC
    `, params);

    if (!rows.length) {
      return res.status(404).send('No hay facturas para exportar con los filtros actuales.');
    }

    // ================= CREAR EXCEL =================
    const workbook = new ExcelJS.Workbook();
    const nombresMes = [
      '', 'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
      'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
    ];

    // Agrupar por mes
    const porMes = {}; // { 1: [facturas], 2: [...], ... }

    for (const f of rows) {
      const mes = f.mes_num || 0;
      if (!porMes[mes]) porMes[mes] = [];
      porMes[mes].push(f);
    }

    // Crear una hoja por cada mes que tenga facturas
    Object.keys(porMes)
      .map(m => parseInt(m, 10))
      .sort((a, b) => a - b)
      .forEach(mes => {
        const lista = porMes[mes];
        const nombreHoja = nombresMes[mes] || `Mes ${mes}`;

        const ws = workbook.addWorksheet(nombreHoja);

        // Encabezados de columnas (puedes ajustar a tu gusto)
        ws.columns = [
          { header: 'Factura', key: 'factura', width: 15 },
          { header: 'Fecha', key: 'fecha', width: 12 },
          { header: 'Cliente', key: 'cliente', width: 30 },
          { header: 'RFC', key: 'rfc', width: 18 },
          { header: 'Producto (clave)', key: 'productoClave', width: 18 },
          { header: 'Descripción', key: 'productoNombre', width: 40 },
          { header: 'ODC', key: 'odc', width: 18 },
          { header: 'Folio fiscal', key: 'folio_fiscal', width: 32 },
          { header: 'Monto', key: 'monto', width: 18 },
          { header: 'Estado', key: 'estado', width: 12 },
          { header: 'Marcado', key: 'marcado', width: 10 },
          { header: 'Estatus adm.', key: 'estatus_adm', width: 20 },
          { header: 'Usuario captura', key: 'usuario', width: 25 },
        ];

        // Filas
        lista.forEach(f => {
          let fechaTxt = '';
          if (f.fecha) {
            const d = f.fecha instanceof Date ? f.fecha : new Date(f.fecha);
            const y = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            fechaTxt = `${y}-${mm}-${dd}`;
          }

          ws.addRow({
            factura: f.factura || `${f.serie_factura || ''}-${String(f.numero_factura || '').padStart(3, '0')}`,
            fecha: fechaTxt,
            cliente: f.nombre_cliente || '',
            rfc: f.RFC_cliente || '',
            productoClave: f.clave_catalogo || '',
            productoNombre: f.nombreProdu_catalogo || '',
            odc: f.odc || '',
            folio_fiscal: f.folio_fiscal || '',
            monto: f.monto || 0,
            estado: f.estado || '',
            marcado: f.marcado ? 'Sí' : 'No',
            estatus_adm: f.estatus_administrativo || '',
            usuario: f.nombre_usuario || ''
          });
        });

        // Opcional: formato de moneda en columna "Monto"
        ws.getColumn('monto').numFmt = '"$"#,##0.00;[Red]\-"$"#,##0.00';
        // Opcional: auto-filtro
        ws.autoFilter = {
          from: 'A1',
          to: 'M1'
        };
      });

    // ================= ENVIAR RESPUESTA =================
    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="facturacion_${anio}.xlsx"`
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error('Error exportando facturación a Excel:', err);
    res.status(500).send('Error al exportar facturación');
  }
});


// NUEVA FACTURA (GET)
app.get('/facturacion/nueva', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, claveSSA_catalogo, nombreProdu_catalogo
      FROM catalogo
      ORDER BY nombreProdu_catalogo
    `);

    const [clientes] = await db.query(`
      SELECT id_cliente, nombre_cliente, RFC_cliente
      FROM cliente
      ORDER BY nombre_cliente
    `);

    const hoy = new Date().toISOString().slice(0, 10);
    const seriePorDefecto = 'FD';

    // Filtros actuales (para regresar al mismo periodo tras guardar)
    const filtroMes = req.query.mes || '';
    const filtroAnio = req.query.anio || '';
    const filtroEstado = req.query.estado || '';
    const filtroQ = req.query.q || '';

    res.render('editar_facturacion', {
      usuario: req.session.usuario,
      productos,
      clientes,
      hoy,
      seriePorDefecto,
      editar: false,
      factura: null,
      error: null,
      ruta: 'facturacion',
      filtroMes,
      filtroAnio,
      filtroEstado,
      filtroQ
    });

  } catch (err) {
    console.error('Error cargando formulario de nueva factura:', err);
    res.send('Error cargando formulario de nueva factura');
  }
});

// EDITAR FACTURA (GET)
app.get('/facturacion/editar/:id_factura', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    const id = parseInt(req.params.id_factura, 10);
    if (isNaN(id)) {
      return res.send('ID de factura inválido');
    }

    const [[factura]] = await db.query(`
      SELECT *
      FROM facturacion
      WHERE id_factura = ?
    `, [id]);

    if (!factura) {
      return res.send('Factura no encontrada');
    }

    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, claveSSA_catalogo, nombreProdu_catalogo
      FROM catalogo
      ORDER BY nombreProdu_catalogo
    `);

    const [clientes] = await db.query(`
      SELECT id_cliente, nombre_cliente, RFC_cliente
      FROM cliente
      ORDER BY nombre_cliente
    `);

    const fechaIso = factura.fecha
      ? (factura.fecha.toISOString ? factura.fecha.toISOString().slice(0, 10) : factura.fecha)
      : '';

    // Filtros actuales
    const filtroMes = req.query.mes || '';
    const filtroAnio = req.query.anio || '';
    const filtroEstado = req.query.estado || '';
    const filtroQ = req.query.q || '';

    res.render('editar_facturacion', {
      usuario: req.session.usuario,
      productos,
      clientes,
      hoy: fechaIso,
      seriePorDefecto: factura.serie_factura,
      editar: true,
      factura,
      error: null,
      ruta: 'facturacion',
      filtroMes,
      filtroAnio,
      filtroEstado,
      filtroQ
    });
  } catch (err) {
    console.error('Error cargando edición de factura:', err);
    res.send('Error cargando edición de factura');
  }
});

// GUARDAR NUEVA FACTURA (POST)
app.post('/facturacion/nueva', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    let {
      serie_factura,
      numero_factura,
      fecha,
      producto_fk,
      cliente_fk,
      odc,
      folio_fiscal,
      monto,
      estado,
      marcado,
      estatus_administrativo,
      // filtros del listado (pueden venir vacíos)
      filtro_mes,
      filtro_anio,
      filtro_estado,
      filtro_q
    } = req.body;

    const usuario = req.session.usuario;

    // 🔹 Si no vinieron filtros en el form, tomarlos de sesión (mantener filtros)
    if (!filtro_mes && !filtro_anio && !filtro_estado && !filtro_q && req.session.filtrosFacturacion) {
      const f = req.session.filtrosFacturacion;
      filtro_mes = f.mes || '';
      filtro_anio = f.anio || '';
      filtro_estado = f.estado || '';
      filtro_q = f.q || '';
    }

    // Limpia serie permitiendo que escriban "FD", "fd-22", etc.
    let rawSerie = (serie_factura || 'FD').trim().toUpperCase();
    const matchSerie = rawSerie.match(/^([A-ZÑ0-9]+?)(?:[-\s]*([0-9]+))?$/);
    let serie = rawSerie;
    let numeroEnSerie = null;
    if (matchSerie) {
      serie = matchSerie[1]; // texto antes del número
      if (matchSerie[2]) {
        numeroEnSerie = parseInt(matchSerie[2], 10);
      }
    }

    if (!serie) throw new Error('La serie de la factura es obligatoria.');
    if (!fecha) throw new Error('La fecha de la factura es obligatoria.');
    if (!producto_fk) throw new Error('Debe seleccionarse un producto.');
    if (!folio_fiscal) throw new Error('El folio fiscal es obligatorio.');

    const estadoValido = ['pagado', 'pendiente', 'cancelado'].includes(estado)
      ? estado
      : 'pendiente';

    const marcadoVal = marcado ? 1 : 0;

    const estatusPermitidos = ['Aprobado', 'En proceso', 'Sin contra recibo', 'N/A'];
    const estatusAdmVal = estatusPermitidos.includes(estatus_administrativo)
      ? estatus_administrativo
      : 'N/A';

    const montoNum = parseFloat(monto || '0');
    if (isNaN(montoNum) || montoNum <= 0) {
      throw new Error('El monto debe ser un número mayor a 0.');
    }

    // Número de factura:
    // 1) Si el usuario lo escribió, se respeta
    // 2) Si lo dejó vacío pero la serie traía número (FD-23), usamos ese
    // 3) Si no, buscamos consecutivo en BD
    let numFact = parseInt(numero_factura, 10);
    if (isNaN(numFact) || numFact < 0) {
      if (numeroEnSerie !== null && !isNaN(numeroEnSerie)) {
        numFact = numeroEnSerie;
      } else {
        const [rows] = await db.query(`
          SELECT IFNULL(MAX(numero_factura), -1) AS max_num
          FROM facturacion
          WHERE serie_factura = ?
        `, [serie]);
        numFact = rows[0].max_num + 1;
      }
    }

    const facturaTexto = `${serie}-${String(numFact).padStart(3, '0')}`;
    const clienteFkFinal = cliente_fk ? parseInt(cliente_fk, 10) : null;

    await db.query(`
      INSERT INTO facturacion (
        serie_factura,
        numero_factura,
        factura,
        odc,
        producto_fk,
        folio_fiscal,
        monto,
        estado,
        marcado,
        estatus_administrativo,
        fecha,
        cliente_fk,
        usuario_fk
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      serie,
      numFact,
      facturaTexto,
      odc || null,
      parseInt(producto_fk, 10),
      folio_fiscal,
      montoNum,
      estadoValido,
      marcadoVal,
      estatusAdmVal,
      fecha,
      clienteFkFinal,
      usuario ? usuario.id_usuario : null
    ]);

    // Armamos redirect conservando filtros (si existen)
    let redirectUrl = '/facturacion';
    const query = [];

    if (filtro_mes) query.push('mes=' + encodeURIComponent(filtro_mes));
    if (filtro_anio) query.push('anio=' + encodeURIComponent(filtro_anio));
    if (filtro_estado) query.push('estado=' + encodeURIComponent(filtro_estado));
    if (filtro_q) query.push('q=' + encodeURIComponent(filtro_q));

    // Si no venían filtros ni hay en sesión, usamos el mes/año de la fecha
    if (query.length === 0 && fecha) {
      const fechaObj = new Date(fecha);
      const mes = fechaObj.getMonth() + 1;
      const anio = fechaObj.getFullYear();
      query.push('mes=' + encodeURIComponent(mes));
      query.push('anio=' + encodeURIComponent(anio));
    }

    if (query.length > 0) {
      redirectUrl += '?' + query.join('&');
    }

    res.redirect(redirectUrl);

  } catch (err) {
    console.error('Error guardando factura nueva:', err);
    try {
      const [productos] = await db.query(`
        SELECT id_catalogo, clave_catalogo, claveSSA_catalogo, nombreProdu_catalogo
        FROM catalogo
        ORDER BY nombreProdu_catalogo
      `);

      const [clientes] = await db.query(`
        SELECT id_cliente, nombre_cliente, RFC_cliente
        FROM cliente
        ORDER BY nombre_cliente
      `);

      const hoy = req.body.fecha || new Date().toISOString().slice(0, 10);
      const seriePorDefecto = req.body.serie_factura || 'FD';

      res.render('editar_facturacion', {
        usuario: req.session.usuario,
        productos,
        clientes,
        hoy,
        seriePorDefecto,
        editar: false,
        factura: null,
        error: err.message || 'Error al guardar la factura',
        ruta: 'facturacion',
        filtroMes: req.body.filtro_mes || '',
        filtroAnio: req.body.filtro_anio || '',
        filtroEstado: req.body.filtro_estado || '',
        filtroQ: req.body.filtro_q || ''
      });
    } catch (err2) {
      console.error('Error cargando formulario tras fallo de guardado:', err2);
      res.send('Error al guardar la factura');
    }
  }
});

// GUARDAR EDICIÓN DE FACTURA (POST)
app.post('/facturacion/editar/:id_factura', estaLogueado, soloAdminYFacturacion, async (req, res) => {
  try {
    const id = parseInt(req.params.id_factura, 10);
    if (isNaN(id)) throw new Error('ID de factura inválido.');

    let {
      serie_factura,
      numero_factura,
      fecha,
      producto_fk,
      cliente_fk,
      odc,
      folio_fiscal,
      monto,
      estado,
      marcado,
      estatus_administrativo,
      // filtros del listado (pueden venir vacíos)
      filtro_mes,
      filtro_anio,
      filtro_estado,
      filtro_q
    } = req.body;

    // 🔹 Si no vinieron filtros en el form, tomarlos de sesión (mantener filtros)
    if (!filtro_mes && !filtro_anio && !filtro_estado && !filtro_q && req.session.filtrosFacturacion) {
      const f = req.session.filtrosFacturacion;
      filtro_mes = f.mes || '';
      filtro_anio = f.anio || '';
      filtro_estado = f.estado || '';
      filtro_q = f.q || '';
    }

    if (!serie_factura) throw new Error('La serie de la factura es obligatoria.');
    if (!fecha) throw new Error('La fecha de la factura es obligatoria.');
    if (!producto_fk) throw new Error('Debe seleccionarse un producto.');
    if (!folio_fiscal) throw new Error('El folio fiscal es obligatorio.');

    const estadoValido = ['pagado', 'pendiente', 'cancelado'].includes(estado)
      ? estado
      : 'pendiente';

    const marcadoVal = marcado ? 1 : 0;

    const estatusPermitidos = ['Aprobado', 'En proceso', 'Sin contra recibo', 'N/A'];
    const estatusAdmVal = estatusPermitidos.includes(estatus_administrativo)
      ? estatus_administrativo
      : 'N/A';

    const montoNum = parseFloat(monto || '0');
    if (isNaN(montoNum) || montoNum <= 0) {
      throw new Error('El monto debe ser un número mayor a 0.');
    }

    let numFact = parseInt(numero_factura, 10);
    if (isNaN(numFact)) throw new Error('Número de factura inválido.');

    // Limpieza de serie básica (quitando número si escriben "FD-22")
    let rawSerie = (serie_factura || '').trim().toUpperCase();
    const matchSerie = rawSerie.match(/^([A-ZÑ0-9]+?)(?:[-\s]*[0-9]+)?$/);
    let serie = rawSerie;
    if (matchSerie) {
      serie = matchSerie[1];
    }

    const facturaTexto = `${serie}-${String(numFact).padStart(3, '0')}`;
    const clienteFkFinal = cliente_fk ? parseInt(cliente_fk, 10) : null;

    await db.query(`
      UPDATE facturacion
      SET
        serie_factura          = ?,
        numero_factura         = ?,
        factura                = ?,
        odc                    = ?,
        producto_fk            = ?,
        folio_fiscal           = ?,
        monto                  = ?,
        estado                 = ?,
        marcado                = ?,
        estatus_administrativo = ?,
        fecha                  = ?,
        cliente_fk             = ?
      WHERE id_factura = ?
    `, [
      serie,
      numFact,
      facturaTexto,
      odc || null,
      parseInt(producto_fk, 10),
      folio_fiscal,
      montoNum,
      estadoValido,
      marcadoVal,
      estatusAdmVal,
      fecha,
      clienteFkFinal,
      id
    ]);

    // Redirección conservando filtros
    let redirectUrl = '/facturacion';
    const query = [];

    if (filtro_mes) query.push('mes=' + encodeURIComponent(filtro_mes));
    if (filtro_anio) query.push('anio=' + encodeURIComponent(filtro_anio));
    if (filtro_estado) query.push('estado=' + encodeURIComponent(filtro_estado));
    if (filtro_q) query.push('q=' + encodeURIComponent(filtro_q));

    if (query.length === 0 && fecha) {
      const fechaObj = new Date(fecha);
      const mes = fechaObj.getMonth() + 1;
      const anio = fechaObj.getFullYear();
      query.push('mes=' + encodeURIComponent(mes));
      query.push('anio=' + encodeURIComponent(anio));
    }

    if (query.length > 0) {
      redirectUrl += '?' + query.join('&');
    }

    res.redirect(redirectUrl);

  } catch (err) {
    console.error('Error actualizando factura:', err);
    try {
      const id = parseInt(req.params.id_factura, 10);

      const [[factura]] = await db.query(`
        SELECT *
        FROM facturacion
        WHERE id_factura = ?
      `, [id]);

      const [productos] = await db.query(`
        SELECT id_catalogo, clave_catalogo, claveSSA_catalogo, nombreProdu_catalogo
        FROM catalogo
        ORDER BY nombreProdu_catalogo
      `);

      const [clientes] = await db.query(`
        SELECT id_cliente, nombre_cliente, RFC_cliente
        FROM cliente
        ORDER BY nombre_cliente
      `);

      const fechaIso = req.body.fecha || (factura.fecha
        ? (factura.fecha.toISOString ? factura.fecha.toISOString().slice(0, 10) : factura.fecha)
        : '');

      res.render('editar_facturacion', {
        usuario: req.session.usuario,
        productos,
        clientes,
        hoy: fechaIso,
        seriePorDefecto: req.body.serie_factura || factura.serie_factura,
        editar: true,
        factura,
        error: err.message || 'Error al actualizar la factura',
        ruta: 'facturacion',
        filtroMes: req.body.filtro_mes || '',
        filtroAnio: req.body.filtro_anio || '',
        filtroEstado: req.body.filtro_estado || '',
        filtroQ: req.body.filtro_q || ''
      });
    } catch (err2) {
      console.error('Error recargando formulario de edición:', err2);
      res.send('Error al actualizar la factura');
    }
  }
});


/* Alias útiles */
app.get('/cotizacion/nueva', (req, res) => res.redirect(302, '/cotizaciones/nueva'));
app.post('/cotizacion/nueva', (req, res) => res.redirect(307, '/cotizaciones/nueva'));
app.get('/cotizacion/editar/:id', (req, res) => res.redirect(302, `/cotizaciones/editar/${req.params.id}`));
app.post('/cotizacion/editar/:id', (req, res) => res.redirect(307, `/cotizaciones/editar/${req.params.id}`));

/* ===== Server ===== */
const PORT = 3005;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
