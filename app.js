const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const db = require('./db');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));

app.use(session({
  secret: 'NashiR',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 }
}));


// ======================== MIDDLEWARES ========================
function estaLogueado(req, res, next) {
  if (req.session?.usuario) return next();
  res.redirect('/acceso');
}

function esAdmin(req, res, next) {
  if (req.session?.usuario?.tipo_usuario === 'administrador') return next();
  res.redirect('/catalogo');
}

// ======================== LOGIN ========================
app.get('/', (req, res) => req.session.destroy(() => res.redirect('/acceso')));

app.get('/acceso', (req, res) => {
  res.render('acceso', { error: null });
});

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;

  try {
    // Verificamos el usuario con los campos correctos de la tabla USUARIO
    const [results] = await db.query(
      `SELECT * FROM USUARIO 
       WHERE BINARY TRIM(userName) = ? 
       AND BINARY TRIM(contraseña_usuario) = ?`,
      [usuario, password]
    );

    if (results.length > 0) {
      req.session.usuario = results[0];
      res.redirect('/catalogo');
    } else {
      res.render('acceso', { error: 'Usuario o contraseña incorrectos' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Error en el servidor');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/acceso');
});

// ======================== USUARIOS ========================
app.get('/usuarios', estaLogueado, esAdmin, async (req, res) => {
  try {
    const [usuarios] = await db.query('SELECT * FROM USUARIO');
    res.render('usuario', { usuarios, usuario: req.session.usuario });
  } catch (err) {
    console.error(err);
    res.send('Error cargando usuarios');
  }
});

app.get('/usuarios/nuevo', estaLogueado, esAdmin, (req, res) => {
  res.render('editar_usuario', { usuarioData: {}, editar: false, usuario: req.session.usuario, error: null });
});

app.post('/usuarios/nuevo', estaLogueado, esAdmin, async (req, res) => {
  const { userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, contraseña_usuario } = req.body;
  try {
    const [existente] = await db.query(
      'SELECT * FROM USUARIO WHERE BINARY TRIM(userName) = ?',
      [userName]
    );

    if (existente.length > 0) {
      return res.render('editar_usuario', {
        usuarioData: req.body,
        editar: false,
        usuario: req.session.usuario,
        error: 'El nombre de usuario ya existe'
      });
    }

    await db.query(
      `INSERT INTO USUARIO (userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, contraseña_usuario, fechaRegistro_usuario)
       VALUES (?, ?, ?, ?, ?, ?, CURDATE())`,
      [userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, contraseña_usuario]
    );

    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al agregar usuario');
  }
});

app.get('/usuarios/editar/:id', estaLogueado, esAdmin, async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM USUARIO WHERE id_usuario = ?', [req.params.id]);
    if (!results.length) return res.send('Usuario no encontrado');

    res.render('editar_usuario', {
      usuarioData: results[0],
      editar: true,
      usuario: req.session.usuario,
      error: null
    });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar usuario');
  }
});

app.post('/usuarios/editar/:id', estaLogueado, esAdmin, async (req, res) => {
  const { userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, contraseña_usuario } = req.body;
  try {
    await db.query(
      `UPDATE USUARIO 
       SET userName = ?, nombreCompleto = ?, tipo_usuario = ?, telefono_usuario = ?, 
           correo_usuario = ?, contraseña_usuario = ? 
       WHERE id_usuario = ?`,
      [userName, nombreCompleto, tipo_usuario, telefono_usuario, correo_usuario, contraseña_usuario, req.params.id]
    );

    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al actualizar usuario');
  }
});

app.post('/usuarios/eliminar/:id', estaLogueado, esAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM USUARIO WHERE id_usuario = ?', [req.params.id]);
    res.redirect('/usuarios');
  } catch (err) {
    console.error(err);
    res.send('Error al eliminar usuario');
  }
});



// ------------------------ PDF ------------------------
app.get('/reporte', estaLogueado, async (req, res) => {
  try {
    // Consulta inventario
    const [rows] = await db.query(
      `SELECT Producto, Lote, Stock, Caducidad, Dias_Restantes_a_Caducar, Estado FROM inventario`
    );

    // Validar plantilla PDF
    const plantillaPath = path.join(__dirname, 'public', 'hojaBase.pdf');
    if (!fs.existsSync(plantillaPath)) {
      return res.status(404).send("Plantilla PDF no encontrada");
    }

    // Cargar PDF base
    const plantillaBytes = fs.readFileSync(plantillaPath);
    const pdfDoc = await PDFDocument.load(plantillaBytes);
    const page = pdfDoc.getPages()[0];
    const { height } = page.getSize();
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    // Configuración de tabla
    const columnas = ["Producto", "Lote", "Stock", "Caducidad", "Días Restantes", "Estado"];
    const startX = 50;
    let startY = height - 180;
    const colWidths = [120, 60, 50, 80, 80, 80];
    const rowHeight = 25;

    const inventario = [
      columnas,
      ...rows.map(r => [
        r.Producto,
        r.Lote?.toString() ?? "",
        r.Stock?.toString() ?? "",
        r.Caducidad ? r.Caducidad.toISOString().split('T')[0] : "",
        r.Dias_Restantes_a_Caducar?.toString() ?? "",
        r.Estado ?? ""
      ])
    ];

    // Dibujar tabla
    for (let i = 0; i < inventario.length; i++) {
      let x = startX;

      for (let j = 0; j < inventario[i].length; j++) {
        // Fondo para encabezado
        if (i === 0) {
          page.drawRectangle({
            x,
            y: startY - rowHeight,
            width: colWidths[j],
            height: rowHeight,
            color: rgb(0, 0.2, 0.6),
          });
        } else {
          page.drawRectangle({
            x,
            y: startY - rowHeight,
            width: colWidths[j],
            height: rowHeight,
            borderColor: rgb(0, 0, 0),
            borderWidth: 1,
          });
        }

        // Texto de la celda
        page.drawText(inventario[i][j], {
          x: x + 3,
          y: startY - rowHeight + 7,
          size: 10,
          font,
          color: i === 0 ? rgb(1, 1, 1) : rgb(0, 0, 0),
        });

        x += colWidths[j];
      }

      startY -= rowHeight;

      // TODO: controlar salto de página si se llena
    }

    // Generar PDF
    const pdfBytes = await pdfDoc.save();

    // Enviar al navegador
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename=Inventario.pdf');
    res.send(Buffer.from(pdfBytes));

  } catch (err) {
    console.error("Error en /reporte:", err);
    res.status(500).send("Error al generar el reporte PDF");
  }
});


// ======================== CATALOGO ========================
app.get('/catalogo', estaLogueado, async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM catalogo');
    res.render('catalogo', { catalogo: results, usuario: req.session.usuario });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar catálogo');
  }
});

app.get('/catalogo/nuevo', estaLogueado, (req, res) => {
  res.render('editar_catalogo', { medicamento: null, usuario: req.session.usuario });
});

app.post('/catalogo/nuevo', estaLogueado, async (req, res) => {
  const { clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo } = req.body;
  try {
    await db.query(
      `INSERT INTO catalogo (clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo) VALUES (?, ?, ?, ?, ?, ?)`,
      [clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, parseFloat(precioVenta_catalogo), parseFloat(costoUnitario_catalogo)]
    );
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al agregar medicamento');
  }
});

app.get('/catalogo/editar/:id', estaLogueado, async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM catalogo WHERE id_catalogo = ?', [req.params.id]);
    if (!results.length) return res.send('Medicamento no encontrado');
    res.render('editar_catalogo', { medicamento: results[0], usuario: req.session.usuario });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar medicamento');
  }
});

app.post('/catalogo/editar/:id', estaLogueado, async (req, res) => {
  const { clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, precioVenta_catalogo, costoUnitario_catalogo } = req.body;
  try {
    await db.query(
      `UPDATE catalogo SET clave_catalogo = ?, nombreProdu_catalogo = ?, presentacion_catalogo = ?, claveSSA_catalogo = ?, precioVenta_catalogo = ?, costoUnitario_catalogo = ? WHERE id_catalogo = ?`,
      [clave_catalogo, nombreProdu_catalogo, presentacion_catalogo, claveSSA_catalogo, parseFloat(precioVenta_catalogo), parseFloat(costoUnitario_catalogo), req.params.id]
    );
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al actualizar medicamento');
  }
});

app.post('/catalogo/eliminar/:id', estaLogueado, async (req, res) => {
  try {
    const [result] = await db.query('DELETE FROM catalogo WHERE id_catalogo = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.send('Medicamento no encontrado');
    res.redirect('/catalogo');
  } catch (err) {
    console.error(err);
    res.send('Error al eliminar medicamento, verifica que no esté en uso');
  }
});

// ========================= ENTRADAS =========================

// GET: Mostrar todas las entradas
app.get('/entradas', estaLogueado, async (req, res) => {
  try {
    const [entrada] = await db.query(`
      SELECT e.*,
             c.nombreProdu_catalogo AS ProductoNombre,
             i.lote_inventario      AS LoteInventario,
             i.estadoDelProducto_inventario AS EstadoInv
      FROM ENTRADA e
      LEFT JOIN INVENTARIO i
        ON e.producto_FKdeInv = i.id_inventario
      LEFT JOIN CATALOGO c
        ON i.producto_FKinventario = c.id_catalogo
      ORDER BY e.fechaDeEntrada DESC
    `);
    res.render('entradas', { entrada, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando entradas:', err);
    res.send('Error cargando entradas');
  }
});

// GET: Formulario de nueva entrada (misma vista que editar)
app.get('/entradas/nueva', estaLogueado, async (req, res) => {
  try {
    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, nombreProdu_catalogo
      FROM CATALOGO
      ORDER BY nombreProdu_catalogo ASC
    `);

    const entrada = {
      Id: 0,
      Proveedor: '',
      Fecha: new Date(),
      Lote: '',
      Caducidad: '',
      Cantidad: '',
      CostoTotal: '',
      ProductoId: null
    };

    res.render('editar_entrada', {
      editar: false,
      entrada,
      productos,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando productos:', err);
    res.send('Error cargando productos');
  }
});

// POST: Guardar nueva entrada
app.post('/entradas/nueva', estaLogueado, async (req, res) => {
  const { Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total } = req.body;

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[productoExiste]] = await conn.query(
      'SELECT id_catalogo FROM CATALOGO WHERE id_catalogo = ?',
      [Producto]
    );
    if (!productoExiste) {
      await conn.rollback();
      return res.send('❌ Error: El producto no existe en el catálogo.');
    }

    const [[invExiste]] = await conn.query(
      `SELECT id_inventario
         FROM INVENTARIO
        WHERE producto_FKinventario = ? AND lote_inventario = ?
        FOR UPDATE`,
      [Producto, Lote]
    );

    let inventarioId;

    if (invExiste) {
      inventarioId = invExiste.id_inventario;
      await conn.query(
        `UPDATE INVENTARIO
            SET stock_inventario = stock_inventario + ?,
                caducidad_inventario = ?,
                diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                estadoDelProducto_inventario = 'Disponible'
          WHERE id_inventario = ?`,
        [Cantidad, Caducidad, Caducidad, inventarioId]
      );
    } else {
      const [nuevoInv] = await conn.query(
        `INSERT INTO INVENTARIO
          (producto_FKinventario, lote_inventario, stock_inventario, caducidad_inventario, diasRestantes_inventario, estadoDelProducto_inventario)
         VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible')`,
        [Producto, Lote, Number(Cantidad), Caducidad, Caducidad]
      );
      inventarioId = nuevoInv.insertId;
    }

    await conn.query(
      `INSERT INTO ENTRADA
        (proveedor, fechaDeEntrada, lote, caducidad, cantidad, costoTotal_entrada, producto_FKdeInv)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [Proveedor, Fecha_de_entrada, Lote, Caducidad, Number(Cantidad), Costo_Total, inventarioId]
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

// GET: Formulario para editar entrada
app.get('/entradas/editar/:id', estaLogueado, async (req, res) => {
  const entradaId = req.params.id;
  try {
    const [[entrada]] = await db.query(`
      SELECT
        e.id_entrada           AS Id,
        e.proveedor            AS Proveedor,
        e.fechaDeEntrada       AS Fecha,
        e.lote                 AS Lote,
        e.caducidad            AS Caducidad,
        e.cantidad             AS Cantidad,
        e.costoTotal_entrada   AS CostoTotal,
        i.producto_FKinventario AS ProductoId
      FROM ENTRADA e
      LEFT JOIN INVENTARIO i ON i.id_inventario = e.producto_FKdeInv
      WHERE e.id_entrada = ?
    `, [entradaId]);

    if (!entrada) return res.send('Entrada no encontrada');

    const [productos] = await db.query(`
      SELECT id_catalogo, clave_catalogo, nombreProdu_catalogo
      FROM CATALOGO
      ORDER BY nombreProdu_catalogo ASC
    `);

    res.render('editar_entrada', {
      editar: true,
      entrada,
      productos,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando entrada para editar:', err);
    res.send('Error cargando entrada');
  }
});

// POST: Editar entrada (ajuste por delta si no cambia producto/lote)
app.post('/entradas/editar/:id', estaLogueado, async (req, res) => {
  const entradaId = req.params.id;
  const { Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total } = req.body;

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[entradaAnterior]] = await conn.query(
      'SELECT * FROM ENTRADA WHERE id_entrada = ? FOR UPDATE',
      [entradaId]
    );
    if (!entradaAnterior) {
      await conn.rollback();
      return res.send('Entrada original no encontrada');
    }

    const [[invViejo]] = await conn.query(
      'SELECT * FROM INVENTARIO WHERE id_inventario = ? FOR UPDATE',
      [entradaAnterior.producto_FKdeInv]
    );
    if (!invViejo) {
      await conn.rollback();
      return res.send('Inventario original no encontrado');
    }

    const mismoProducto = (Number(invViejo.producto_FKinventario) === Number(Producto));
    const mismoLote = (invViejo.lote_inventario === Lote);

    if (mismoProducto && mismoLote) {
      const delta = Number(Cantidad) - Number(entradaAnterior.cantidad);
      if (delta !== 0) {
        await conn.query(
          `UPDATE INVENTARIO
              SET stock_inventario = stock_inventario + ?,
                  caducidad_inventario = ?,
                  diasRestantes_inventario = DATEDIFF(?, CURDATE())
            WHERE id_inventario = ?`,
          [delta, Caducidad, Caducidad, invViejo.id_inventario]
        );
      }

      await conn.query(
        `UPDATE ENTRADA
            SET proveedor = ?,
                fechaDeEntrada = ?,
                lote = ?,
                caducidad = ?,
                cantidad = ?,
                costoTotal_entrada = ?
          WHERE id_entrada = ?`,
        [Proveedor, Fecha_de_entrada, Lote, Caducidad, Number(Cantidad), Costo_Total, entradaId]
      );
    } else {
      const [[invDestinoExistente]] = await conn.query(
        `SELECT id_inventario
           FROM INVENTARIO
          WHERE producto_FKinventario = ? AND lote_inventario = ?
          FOR UPDATE`,
        [Producto, Lote]
      );

      let inventarioDestinoId;
      if (invDestinoExistente) {
        inventarioDestinoId = invDestinoExistente.id_inventario;
        await conn.query(
          `UPDATE INVENTARIO
              SET stock_inventario = stock_inventario + ?,
                  caducidad_inventario = ?,
                  diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                  estadoDelProducto_inventario = 'Disponible'
            WHERE id_inventario = ?`,
          [Number(Cantidad), Caducidad, Caducidad, inventarioDestinoId]
        );
      } else {
        const [nuevoInv] = await conn.query(
          `INSERT INTO INVENTARIO
            (producto_FKinventario, lote_inventario, stock_inventario, caducidad_inventario, diasRestantes_inventario, estadoDelProducto_inventario)
           VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible')`,
          [Producto, Lote, Number(Cantidad), Caducidad, Caducidad]
        );
        inventarioDestinoId = nuevoInv.insertId;
      }

      await conn.query(
        `UPDATE ENTRADA
            SET proveedor = ?,
                fechaDeEntrada = ?,
                lote = ?,
                caducidad = ?,
                cantidad = ?,
                costoTotal_entrada = ?,
                producto_FKdeInv = ?
          WHERE id_entrada = ?`,
        [Proveedor, Fecha_de_entrada, Lote, Caducidad, Number(Cantidad), Costo_Total, inventarioDestinoId, entradaId]
      );

      await conn.query(
        `UPDATE INVENTARIO
            SET stock_inventario = stock_inventario - ?
          WHERE id_inventario = ?`,
        [Number(entradaAnterior.cantidad), invViejo.id_inventario]
      );

      const [[revViejo]] = await conn.query(
        'SELECT stock_inventario FROM INVENTARIO WHERE id_inventario = ?',
        [invViejo.id_inventario]
      );

      if (revViejo && Number(revViejo.stock_inventario) === 0) {
        const [[refsViejas]] = await conn.query(
          'SELECT COUNT(*) AS cnt FROM ENTRADA WHERE producto_FKdeInv = ?',
          [invViejo.id_inventario]
        );

        if (Number(refsViejas.cnt) === 0) {
          await conn.query('DELETE FROM INVENTARIO WHERE id_inventario = ?', [invViejo.id_inventario]);
        } else {
          await conn.query(
            `UPDATE INVENTARIO
                SET estadoDelProducto_inventario = 'Agotado'
              WHERE id_inventario = ?`,
            [invViejo.id_inventario]
          );
        }
      }
    }

    await conn.commit();
    console.log('✅ Entrada editada correctamente');
    res.redirect('/entradas');
  } catch (err) {
    await conn.rollback();
    console.error('Error editando entrada:', err);
    res.send('Error editando entrada');
  } finally {
    conn.release();
  }
});

// ========================= SALIDAS (ajustado a tu BD + aliases para tu EJS) =========================

app.get('/salidas', estaLogueado, async (req, res) => {
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
          s.folioDeFacturacion_salida AS Folio_de_Facturacion
        FROM SALIDA s
        LEFT JOIN CLIENTE    cl ON cl.id_cliente   = s.id_cliente
        LEFT JOIN INVENTARIO i  ON i.id_inventario = s.id_inventario
        LEFT JOIN CATALOGO   ca ON ca.id_catalogo  = i.producto_FKinventario
        ORDER BY s.fecha_salida DESC
      `);

    res.render('salidas', { salidas, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando salidas:', err);
    res.send('Error cargando salidas');
  }
});

// ========================= SALIDAS: BUSCAR POR ORDEN =========================
app.get('/salidas/buscar', estaLogueado, async (req, res) => {
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
          s.folioDeFacturacion_salida AS Folio_de_Facturacion
        FROM SALIDA s
        LEFT JOIN CLIENTE    cl ON cl.id_cliente   = s.id_cliente
        LEFT JOIN INVENTARIO i  ON i.id_inventario = s.id_inventario
        LEFT JOIN CATALOGO   ca ON ca.id_catalogo  = i.producto_FKinventario
        WHERE s.ordenDeCompra_salida = ?
        ORDER BY s.fecha_salida DESC
      `, [orden]);

    res.render('salidas', { salidas, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error buscando orden de compra:', err);
    res.send('Error buscando orden de compra');
  }
});


// NUEVA: FORMULARIO (clientes/productos + lotes precargados en la vista)
//  - El <select Lote> se llena en el navegador filtrando window.LOTES (sin API).
app.get('/salidas/nueva', estaLogueado, async (req, res) => {
  try {
    // Clientes -> { Id, Nombre }
    const [clientes] = await db.query(`
        SELECT id_cliente AS Id, nombre_cliente AS Nombre
        FROM CLIENTE
        ORDER BY nombre_cliente ASC
      `);

    // Productos con presencia en inventario (stock > 0) -> { Codigo, Nombre }
    const [productos] = await db.query(`
        SELECT
          c.clave_catalogo        AS Codigo,
          c.nombreProdu_catalogo  AS Nombre
        FROM INVENTARIO i
        JOIN CATALOGO c ON c.id_catalogo = i.producto_FKinventario
        WHERE i.stock_inventario > 0
        GROUP BY c.clave_catalogo, c.nombreProdu_catalogo
        ORDER BY c.nombreProdu_catalogo ASC
      `);

    // Lotes disponibles (stock > 0) -> { Producto (Codigo), Lote, Caducidad, Stock }
    const [lotes] = await db.query(`
        SELECT
          c.clave_catalogo        AS Producto,
          i.lote_inventario       AS Lote,
          i.caducidad_inventario  AS Caducidad,
          i.stock_inventario      AS Stock
        FROM INVENTARIO i
        JOIN CATALOGO c ON c.id_catalogo = i.producto_FKinventario
        WHERE i.stock_inventario > 0
        ORDER BY c.nombreProdu_catalogo ASC, i.lote_inventario ASC
      `);

    // Objeto "salida" vacío para reusar la misma vista
    const salida = {
      Id: 0,
      orden_de_compra: '',
      Fecha: new Date(),
      ClienteId: null,
      Producto: '',    // Codigo
      Lote: '',
      Cantidad: '',
      Precio_Venta: '',
      Total_Facturado: '',
      Folio_de_Facturacion: ''
    };

    res.render('editar_salida', { salida, clientes, productos, lotes, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando formulario de nueva salida:', err);
    res.send('Error cargando formulario de nueva salida');
  }
});

// NUEVA: PROCESAR
app.post('/salidas/nueva', estaLogueado, async (req, res) => {
  const conn = await db.getConnection();
  try {
    let { Fecha, ClienteId, Producto, Lote, Cantidad, Precio_Venta, Total_Facturado, orden_de_compra, Folio_de_Facturacion } = req.body;
    const cantidadNum = parseInt(Cantidad, 10);

    await conn.beginTransaction();

    // Convertir Producto (Codigo/clave_catalogo) -> id_catalogo
    const [[cat]] = await conn.query(
      `SELECT id_catalogo FROM CATALOGO WHERE clave_catalogo = ?`,
      [Producto]
    );
    if (!cat) {
      await conn.rollback();
      return res.send(`
          <h2 style="color:red;">Error: Código de producto inválido</h2>
          <a href="/salidas/nueva"><button>Volver</button></a>
        `);
    }

    // Buscar inventario por (id_catalogo, Lote)
    const [[inv]] = await conn.query(`
        SELECT id_inventario, stock_inventario, caducidad_inventario
        FROM INVENTARIO
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

    // Orden de compra (si no viene, usar consecutivo)
    let ordenOC = (orden_de_compra && `${orden_de_compra}`.trim() !== '') ? `${orden_de_compra}`.trim() : null;
    if (!ordenOC) {
      const [[row]] = await conn.query(
        `SELECT * FROM CONSECUTIVO WHERE nombre = 'orden_de_compra' FOR UPDATE`
      );
      if (!row) {
        await conn.query(`INSERT INTO CONSECUTIVO (nombre, ultimoValor) VALUES ('orden_de_compra', 0)`);
      }
      const [[row2]] = await conn.query(
        `SELECT * FROM CONSECUTIVO WHERE nombre = 'orden_de_compra' FOR UPDATE`
      );
      const siguiente = Number(row2.ultimoValor) + 1;
      await conn.query(
        `UPDATE CONSECUTIVO SET ultimoValor = ? WHERE id_consecutivo = ?`,
        [siguiente, row2.id_consecutivo]
      );
      ordenOC = String(siguiente);
    }

    // Insertar salida
    await conn.query(`
        INSERT INTO SALIDA
          (ordenDeCompra_salida, fecha_salida, id_cliente, id_inventario, lote, cantidad,
          precioDeVenta_salida, totalFacturado_salida, folioDeFacturacion_salida)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
      ordenOC,
      Fecha,
      ClienteId,
      inv.id_inventario,
      Lote,
      cantidadNum,
      Precio_Venta,
      Total_Facturado,
      Folio_de_Facturacion || null
    ]);

    // Descontar inventario
    await conn.query(`
        UPDATE INVENTARIO
          SET stock_inventario = stock_inventario - ?,
              diasRestantes_inventario = DATEDIFF(caducidad_inventario, CURDATE())
        WHERE id_inventario = ?
      `, [cantidadNum, inv.id_inventario]);

    // Si quedó en 0, no borrar (evita cascada), solo marcar Agotado
    const [[rev]] = await conn.query(
      `SELECT stock_inventario FROM INVENTARIO WHERE id_inventario = ?`,
      [inv.id_inventario]
    );
    if (rev && Number(rev.stock_inventario) === 0) {
      await conn.query(`
          UPDATE INVENTARIO
            SET estadoDelProducto_inventario = 'Agotado'
          WHERE id_inventario = ?
        `, [inv.id_inventario]);
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

// EDITAR: FORMULARIO (aliaseado EXACTO a tu EJS)
app.get('/salidas/editar/:id', estaLogueado, async (req, res) => {
  const salidaId = req.params.id;
  try {
    // salida -> con los nombres que espera tu EJS
    const [[salida]] = await db.query(`
        SELECT
          s.id_salida                  AS Id,
          s.ordenDeCompra_salida      AS orden_de_compra,
          s.fecha_salida              AS Fecha,
          s.id_cliente                AS ClienteId,
          ca.clave_catalogo           AS Producto,         -- Codigo para tu <select>
          s.lote                      AS Lote,
          s.cantidad                  AS Cantidad,
          s.precioDeVenta_salida      AS Precio_Venta,
          s.totalFacturado_salida     AS Total_Facturado,
          s.folioDeFacturacion_salida AS Folio_de_Facturacion,
          s.id_inventario             AS id_inventario
        FROM SALIDA s
        LEFT JOIN INVENTARIO i ON i.id_inventario = s.id_inventario
        LEFT JOIN CATALOGO  ca ON ca.id_catalogo   = i.producto_FKinventario
        WHERE s.id_salida = ?
      `, [salidaId]);

    if (!salida) return res.send('Salida no encontrada');

    // clientes -> { Id, Nombre }
    const [clientes] = await db.query(`
        SELECT id_cliente AS Id, nombre_cliente AS Nombre
        FROM CLIENTE
        ORDER BY nombre_cliente ASC
      `);

    // productos -> { Codigo, Nombre } (con presencia en inventario)
    const [productos] = await db.query(`
        SELECT
          c.clave_catalogo        AS Codigo,
          c.nombreProdu_catalogo  AS Nombre
        FROM INVENTARIO i
        JOIN CATALOGO c ON c.id_catalogo = i.producto_FKinventario
        GROUP BY c.clave_catalogo, c.nombreProdu_catalogo
        ORDER BY c.nombreProdu_catalogo ASC
      `);

    // Lotes que se enviarán a la vista para que el JS los filtre allí
    // Incluye el lote actual aunque esté en 0
    const [lotes] = await db.query(`
        SELECT
          c.clave_catalogo        AS Producto,
          i.lote_inventario       AS Lote,
          i.caducidad_inventario  AS Caducidad,
          i.stock_inventario      AS Stock
        FROM INVENTARIO i
        JOIN CATALOGO c ON c.id_catalogo = i.producto_FKinventario
        WHERE (i.stock_inventario > 0) OR (i.id_inventario = ?)
        ORDER BY c.nombreProdu_catalogo ASC, i.lote_inventario ASC
      `, [salida.id_inventario]);

    res.render('editar_salida', { salida, clientes, productos, lotes, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando salida para editar:', err);
    res.send('Error cargando salida para editar');
  }
});


// EDITAR: PROCESAR (Producto llega como Codigo -> resolver a id_catalogo)
// Manejo por DELTA si no cambia el inventario (mismo producto+lote)
app.post('/salidas/editar/:id', estaLogueado, async (req, res) => {
  const salidaId = req.params.id;
  const conn = await db.getConnection();
  try {
    const {
      Fecha, ClienteId, Producto, Lote, Cantidad,
      Precio_Venta, Total_Facturado, orden_de_compra, Folio_de_Facturacion
    } = req.body;

    const nuevaCant = parseInt(Cantidad, 10);

    await conn.beginTransaction();

    // 1) Salida original (incluye inventario actual y cantidad original)
    const [[original]] = await conn.query(`
      SELECT s.id_salida, s.cantidad AS cant_original, s.id_inventario AS inv_original,
             s.ordenDeCompra_salida
      FROM SALIDA s
      WHERE s.id_salida = ?
      FOR UPDATE
    `, [salidaId]);

    if (!original) {
      await conn.rollback();
      return res.send('Salida original no encontrada');
    }

    const cantOriginal = Number(original.cant_original || 0);

    // 2) Resolver Codigo -> id_catalogo
    const [[cat]] = await conn.query(
      `SELECT id_catalogo FROM CATALOGO WHERE clave_catalogo = ?`,
      [Producto]
    );
    if (!cat) {
      await conn.rollback();
      return res.send(`
        <h2 style="color:red;">Error: Código de producto inválido</h2>
        <a href="/salidas"><button class="btn">Volver</button></a>
      `);
    }

    // 3) Inventario destino (producto + lote)
    const [[invDestino]] = await conn.query(`
      SELECT id_inventario, stock_inventario, caducidad_inventario
      FROM INVENTARIO
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

    // 4) ¿Cambió el inventario (producto/lote)?
    const mismoInventario = (Number(invDestino.id_inventario) === Number(original.inv_original));

    if (mismoInventario) {
      // --- Caso A: MISMO inventario -> ajustar por DELTA ---
      // stock actual ya es "stock tras la salida original"
      const stockActual = Number(invDestino.stock_inventario);
      const delta = nuevaCant - cantOriginal; // + => pedir más stock; - => regresar stock

      // Validación: si delta > 0, debe haber stock suficiente
      if (delta > 0 && delta > stockActual) {
        await conn.rollback();
        return res.send(`
          <h2 style="color:red;">Error: La cantidad excede el stock disponible para este ajuste</h2>
          <a href="/salidas"><button class="btn">Volver</button></a>
        `);
      }

      // Aplicar el delta
      const stockNuevo = stockActual - delta;
      await conn.query(`
        UPDATE INVENTARIO
           SET stock_inventario = ?
         WHERE id_inventario = ?
      `, [stockNuevo, invDestino.id_inventario]);

      // Actualizar salida
      await conn.query(`
        UPDATE SALIDA
           SET fecha_salida              = ?,
               id_cliente                = ?,
               id_inventario             = ?,   -- se mantiene igual
               lote                      = ?,
               cantidad                  = ?,
               precioDeVenta_salida      = ?,
               totalFacturado_salida     = ?,
               ordenDeCompra_salida      = ?,
               folioDeFacturacion_salida = ?
         WHERE id_salida = ?
      `, [
        Fecha,
        ClienteId,
        invDestino.id_inventario,
        Lote,
        nuevaCant,
        Precio_Venta,
        Total_Facturado,
        (orden_de_compra && `${orden_de_compra}`.trim() !== '' ? `${orden_de_compra}`.trim() : original.ordenDeCompra_salida),
        Folio_de_Facturacion || null,
        salidaId
      ]);
    } else {
      // --- Caso B: CAMBIÓ de inventario -> revertir y aplicar completo ---
      // 1) Revertir al inventario original
      if (original.inv_original) {
        await conn.query(`
          UPDATE INVENTARIO
             SET stock_inventario = stock_inventario + ?
           WHERE id_inventario = ?
        `, [cantOriginal, original.inv_original]);
      }

      // 2) Validar stock en inventario nuevo para la nueva cantidad
      if (Number(invDestino.stock_inventario) < nuevaCant) {
        await conn.rollback();
        return res.send(`
          <h2 style="color:red;">Error: Stock insuficiente en el nuevo lote seleccionado</h2>
          <a href="/salidas"><button class="btn">Volver</button></a>
        `);
      }

      // 3) Descontar del inventario nuevo
      await conn.query(`
        UPDATE INVENTARIO
           SET stock_inventario = stock_inventario - ?
         WHERE id_inventario = ?
      `, [nuevaCant, invDestino.id_inventario]);

      // 4) Actualizar salida con nuevo inventario
      await conn.query(`
        UPDATE SALIDA
           SET fecha_salida              = ?,
               id_cliente                = ?,
               id_inventario             = ?,
               lote                      = ?,
               cantidad                  = ?,
               precioDeVenta_salida      = ?,
               totalFacturado_salida     = ?,
               ordenDeCompra_salida      = ?,
               folioDeFacturacion_salida = ?
         WHERE id_salida = ?
      `, [
        Fecha,
        ClienteId,
        invDestino.id_inventario,
        Lote,
        nuevaCant,
        Precio_Venta,
        Total_Facturado,
        (orden_de_compra && `${orden_de_compra}`.trim() !== '' ? `${orden_de_compra}`.trim() : original.ordenDeCompra_salida),
        Folio_de_Facturacion || null,
        salidaId
      ]);

      // 5) Si el inventario original quedó en 0, marcar Agotado (opcional)
      if (original.inv_original) {
        const [[revViejo]] = await conn.query(
          `SELECT stock_inventario FROM INVENTARIO WHERE id_inventario = ?`,
          [original.inv_original]
        );
        if (revViejo && Number(revViejo.stock_inventario) === 0) {
          await conn.query(`
            UPDATE INVENTARIO
               SET estadoDelProducto_inventario = 'Agotado'
             WHERE id_inventario = ?
          `, [original.inv_original]);
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

// ========================= Servir el JS externo SIN API (usa window.LOTES) =========================
app.get('/js/form_salida.js', (req, res) => {
  res.type('application/javascript').send(`

// =================== Lógica principal ===================
document.addEventListener('DOMContentLoaded', function () {
  var productoSelect = document.getElementById('Producto');
  var loteSelect = document.getElementById('Lote');
  var cantidadInput = document.getElementById('Cantidad');
  var LOTES = window.LOTES || [];
  var SALIDA = window.SALIDA || { Producto: null, Lote: null, CantidadOriginal: 0 };

  function poblarLotes() {
    var codigo = productoSelect.value;
    loteSelect.innerHTML = '<option value="">-- Selecciona un lote --</option>';
    loteSelect.disabled = true;

    if (!codigo) { actualizarMax(); return; }

    var filtrados = LOTES.filter(function (l) { return String(l.Producto) === String(codigo); });

    filtrados.forEach(function (l) {
      var opt = document.createElement('option');
      opt.value = l.Lote;
      opt.textContent = l.Lote + ' (stock: ' + l.Stock + ')';
      opt.dataset.stock = l.Stock;
      loteSelect.appendChild(opt);
    });

    loteSelect.disabled = filtrados.length === 0;

    // Mantener seleccionado el lote actual si existe (edición)
    var actual = loteSelect.getAttribute('data-current-lote') || SALIDA.Lote;
    if (actual) {
      var found = Array.from(loteSelect.options).find(function (o) { return o.value === actual; });
      if (found) { found.selected = true; }
    }

    actualizarMax();
  }

  function actualizarMax() {
    var sel = loteSelect.selectedOptions[0];
    if (sel && sel.dataset.stock) {
      var base = parseInt(sel.dataset.stock, 10);
      var mismoProd = String(productoSelect.value) === String(SALIDA.Producto);
      var mismoLote = String(sel.value) === String(SALIDA.Lote);
      var maxPermitido = (mismoProd && mismoLote)
        ? (base + Number(SALIDA.CantidadOriginal || 0))
        : base;
      cantidadInput.max = maxPermitido;
    } else {
      cantidadInput.removeAttribute('max');
    }
  }

  productoSelect.addEventListener('change', poblarLotes);
  loteSelect.addEventListener('change', actualizarMax);

  // Inicializar
  poblarLotes();
  actualizarMax();
});

// =================== Código específico para NUEVA salida ===================
if (window.location.pathname.includes('/salidas/nueva')) {
  console.log('Formulario: Nueva salida');
  // Aquí puedes agregar lógica adicional para nuevas salidas si la necesitas
}

// =================== Código específico para EDITAR salida ===================
if (window.location.pathname.includes('/salidas/editar')) {
  console.log('Formulario: Editar salida');
  // Aquí puedes agregar lógica extra para edición (por ejemplo, validaciones o mensajes)
}

  `);
});


// ========================= INVENTARIO =========================
// GET: Mostrar inventario (compatible con tu EJS actual)
app.get('/inventario', estaLogueado, async (req, res) => {
  try {
    const [inventario] = await db.query(`
      SELECT
        i.id_inventario,
        i.producto_FKinventario,
        i.lote_inventario,
        i.stock_inventario,
        i.caducidad_inventario,

        -- Aliases que tu EJS ya consume
        c.nombreProdu_catalogo  AS ProductoNombre,
        c.clave_catalogo        AS Codigo,
        c.presentacion_catalogo AS Presentacion,
        c.precioVenta_catalogo,
        c.costoUnitario_catalogo,

        -- DÍAS RESTANTES (con ambos nombres por compatibilidad con tu EJS)
        DATEDIFF(i.caducidad_inventario, CURDATE()) AS diasRestantes_inventario,
        DATEDIFF(i.caducidad_inventario, CURDATE()) AS DiasRestantes,

        -- ESTADO con los textos exactos que usa tu EJS
        CASE
          WHEN i.caducidad_inventario IS NULL THEN 'Vigente'              -- si no hay fecha, lo tratamos como vigente
          WHEN i.caducidad_inventario < CURDATE() THEN 'Caducado'
          WHEN DATEDIFF(i.caducidad_inventario, CURDATE()) <= 30 THEN 'Próximo a vencer'
          ELSE 'Vigente'
        END AS estadoDelProducto_inventario
      FROM INVENTARIO i
      JOIN CATALOGO c
        ON i.producto_FKinventario = c.id_catalogo
      ORDER BY i.caducidad_inventario ASC
    `);

    res.render('inventario', { inventario, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando inventario:', err);
    res.send('Error cargando inventario');
  }
});

// ------------------------ CLIENTES ------------------------

// Listar clientes
app.get('/clientes', estaLogueado, async (req, res) => {
  try {
    const [resultados] = await db.query(`
      SELECT
        id_cliente        AS Id,
        nombre_cliente    AS Nombre,
        RFC_cliente       AS RFC,
        direccion_cliente AS Direccion,
        telefono_cliente  AS Telefono,
        correo_cliente    AS Correo
      FROM CLIENTE
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

// ---------- NUEVO: usar la MISMA vista para crear ----------

// GET: Formulario NUEVO (misma vista que editar)
app.get('/clientes/nuevo', estaLogueado, async (req, res) => {
  // objeto vacío compatible con el EJS
  const cliente = {
    Id: 0,
    Nombre: '',
    RFC: '',
    Direccion: '',
    Telefono: '',
    Correo: ''
  };

  res.render('editar_cliente', {
    editar: false,
    cliente,
    usuario: req.session.usuario
  });
});

// POST: Guardar NUEVO (ruta alineada con el EJS)
app.post('/clientes/nuevo', estaLogueado, async (req, res) => {
  const { Nombre, RFC, Direccion, Telefono, Correo } = req.body;
  const sql = `
    INSERT INTO CLIENTE
      (nombre_cliente, RFC_cliente, direccion_cliente, telefono_cliente, correo_cliente)
    VALUES (?, ?, ?, ?, ?)
  `;
  try {
    await db.query(sql, [Nombre, RFC, Direccion, Telefono, Correo]);
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error al agregar cliente:', err);
    res.send('Error al agregar cliente');
  }
});

// ---------- EDITAR: usa la MISMA vista ----------

// GET: Formulario EDITAR
app.get('/clientes/editar/:id', estaLogueado, async (req, res) => {
  const clienteId = req.params.id;
  try {
    const [resultados] = await db.query(`
      SELECT
        id_cliente        AS Id,
        nombre_cliente    AS Nombre,
        RFC_cliente       AS RFC,
        direccion_cliente AS Direccion,
        telefono_cliente  AS Telefono,
        correo_cliente    AS Correo
      FROM CLIENTE
      WHERE id_cliente = ?
    `, [clienteId]);

    if (resultados.length === 0) return res.send('Cliente no encontrado');

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

// POST: Procesar EDICIÓN
app.post('/clientes/editar/:id', estaLogueado, async (req, res) => {
  const clienteId = req.params.id;
  const { Nombre, RFC, Direccion, Telefono, Correo } = req.body;

  const sqlUpdate = `
    UPDATE CLIENTE
       SET nombre_cliente = ?,
           RFC_cliente = ?,
           direccion_cliente = ?,
           telefono_cliente = ?,
           correo_cliente = ?
     WHERE id_cliente = ?
  `;
  try {
    await db.query(sqlUpdate, [Nombre, RFC, Direccion, Telefono, Correo, clienteId]);
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error al actualizar cliente:', err);
    res.send('Error al actualizar cliente');
  }
});

// Eliminar cliente
app.post('/clientes/eliminar/:id', estaLogueado, async (req, res) => {
  const clienteId = req.params.id;
  try {
    await db.query('DELETE FROM CLIENTE WHERE id_cliente = ?', [clienteId]);
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error eliminando cliente:', err);
    res.send('Error al eliminar cliente');
  }
});
// ======================================== COTIZACIONES ========================================
// ===== Utilidades de fechas (local) =====
function formatDateLocal(date) { if (!date) return null; const y = date.getFullYear(); const m = String(date.getMonth() + 1).padStart(2, '0'); const d = String(date.getDate()).padStart(2, '0'); return `${y}-${m}-${d}`; }
function parseDateLocal(s) { if (!s) return null; const [y, m, d] = String(s).split('-').map(Number); const dt = new Date(y, m - 1, d); if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) return null; return dt; }
function addDaysLocal(dt, days) { const c = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()); c.setDate(c.getDate() + days); return c; }
function diffDaysLocal(a, b) { const MS = 86400000; const a0 = new Date(a.getFullYear(), a.getMonth(), a.getDate()); const b0 = new Date(b.getFullYear(), b.getMonth(), b.getDate()); return Math.round((b0 - a0) / MS); }
function calcularVigenciaYFechaFin(fechaDeFolio, vigenciaInput, fechaFinInput) {
  const inicio = parseDateLocal(fechaDeFolio);
  if (!inicio) return { vigencia: null, fechaFin: null };
  const vStr = (vigenciaInput ?? '').toString().trim();
  const fStr = (fechaFinInput ?? '').toString().trim();
  let vigencia = (vStr !== '' && !Number.isNaN(Number(vStr))) ? Number(vStr) : null;
  let fechaFin = fStr !== '' ? parseDateLocal(fStr) : null;
  if (vigencia !== null && vigencia >= 0 && !fechaFin) { fechaFin = addDaysLocal(inicio, vigencia); }
  else if ((vigencia === null || Number.isNaN(vigencia)) && fechaFin) { const dias = diffDaysLocal(inicio, fechaFin); vigencia = dias >= 0 ? dias : null; }
  else if (vigencia !== null && fechaFin) { fechaFin = addDaysLocal(inicio, Math.max(0, vigencia)); }
  else { return { vigencia: null, fechaFin: null }; }
  if (vigencia !== null && (!Number.isFinite(vigencia) || vigencia < 0)) vigencia = null;
  const fechaFinStr = fechaFin ? formatDateLocal(fechaFin) : null;
  return { vigencia, fechaFin: fechaFinStr };
}

// === Helpers para CONSECUTIVO(nombre='cotizacion') ===
async function getConsecutivoCotizacionId(conn) {
  const [r] = await conn.query('SELECT id_consecutivo FROM CONSECUTIVO WHERE nombre=? LIMIT 1', ['cotizacion']);
  if (r.length) return r[0].id_consecutivo;
  const [ins] = await conn.query('INSERT INTO CONSECUTIVO (nombre, ultimoValor) VALUES (?,?)', ['cotizacion', 0]);
  return ins.insertId;
}

async function generateFolioIfEmpty(conn, folioInput) {
  const folio = (folioInput ?? '').trim();
  if (folio !== '') return folio; // usar el que escribió el usuario

  // Bloqueo y aumento atómico del consecutivo
  const [cur] = await conn.query('SELECT id_consecutivo, ultimoValor FROM CONSECUTIVO WHERE nombre=? FOR UPDATE', ['cotizacion']);
  let idc, ultimo = 0;
  if (cur.length) { idc = cur[0].id_consecutivo; ultimo = Number(cur[0].ultimoValor || 0); }
  else {
    const [ins] = await conn.query('INSERT INTO CONSECUTIVO (nombre, ultimoValor) VALUES (?,?)', ['cotizacion', 0]);
    idc = ins.insertId; ultimo = 0;
  }
  const siguiente = ultimo + 1;
  await conn.query('UPDATE CONSECUTIVO SET ultimoValor=? WHERE id_consecutivo=?', [siguiente, idc]);

  // Formato del folio visible (ajústalo si quieres)
  return `COT-${String(siguiente).padStart(4, '0')}`;
}

// ============= LISTADO =============
app.get('/cotizaciones', estaLogueado, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
        c.id_cotizacion AS id,

        -- 👇 Este alias sí coincide con el que usas en el EJS
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

        -- 👇 Nombre completo del responsable
        COALESCE(u.nombreCompleto, '—') AS responsableDeLaCotizacion,

        c.estatus_cotizacion           AS estatusDeLaCotizacion,
        c.partidasAsignadas_cotizacion AS partidasAsignadas,
        c.montoMaxAsignado_cotizacion  AS montoMaximoAsignado
      FROM COTIZACION c
      LEFT JOIN USUARIO u
        ON u.id_usuario = c.responsableDeLaCotizacionFK
      ORDER BY c.id_cotizacion DESC
    `);

    res.render('cotizaciones', { usuario: req.session.usuario, cotizaciones: rows });
  } catch (err) {
    console.error('Error cargando cotizaciones:', err);
    res.status(500).send('Error en el servidor');
  }
});


// ============= NUEVA =============

app.get('/cotizaciones/nueva', estaLogueado, async (req, res) => {
  try {
    // Obtener lista de usuarios para el <select>
    const [usuarios] = await db.query(
      'SELECT id_usuario, nombreCompleto AS nombre_usuario FROM USUARIO ORDER BY nombreCompleto ASC'
    );


    res.render('editar_cotizaciones', {
      cotizacion: null,
      usuario: req.session.usuario,
      usuarios, // 👈 Enviamos al EJS
    });
  } catch (err) {
    console.error('Error cargando usuarios:', err);
    res.status(500).send('Error al cargar formulario de cotización');
  }
});

app.post('/cotizaciones/nueva', estaLogueado, async (req, res) => {
  let conn;
  try {
    const {
      folioVisible, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia,
      vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, estatusDeLaCotizacion,
      partidasAsignadas, montoMaximoAsignado, responsableDeLaCotizacion
    } = req.body;

    if (!fechaDeFolio) throw new Error('Fecha de Folio requerida.');

    const { vigencia, fechaFin } = calcularVigenciaYFechaFin(
      fechaDeFolio,
      vigenciaDeLaCotizacion,
      fechaFinDeLaCotizacion
    );

    conn = await db.getConnection();
    await conn.beginTransaction();

    const idConsecutivo = await getConsecutivoCotizacionId(conn);
    const folioParaGuardar = await generateFolioIfEmpty(conn, folioVisible);

    await conn.query(
      `INSERT INTO COTIZACION
       (noDeFolio_FKcotizacion, folio_cotizacion, fechaDeFolio_cotizacion,
        partidasCotizadas_cotizacion, montoMaxCotizado_cotizacion, dependencia_cotizacion,
        vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, responsableDeLaCotizacionFK,
        estatus_cotizacion, partidasAsignadas_cotizacion, montoMaxAsignado_cotizacion)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        idConsecutivo, folioParaGuardar, fechaDeFolio,
        Number(partidasCotizadas || 0), Number(montoMaxCotizado || 0),
        (dependencia ?? '').trim() || null, vigencia, fechaFin,
        Number(responsableDeLaCotizacion) || null, // 👈 FK de usuario
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
// ============= EDITAR =============
app.get('/cotizaciones/editar/:id', estaLogueado, async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await db.query(
      `SELECT
         c.id_cotizacion                AS id,
         c.noDeFolio_FKcotizacion       AS noDeFolioFK,
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
       FROM COTIZACION c
       WHERE c.id_cotizacion = ?`,
      [id]
    );

    if (!rows.length) return res.status(404).send('Cotización no encontrada');
    const c = rows[0];

    // Fechas para inputs type="date"
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

    // Cargar usuarios para el <select>
    const [usuarios] = await db.query(
      'SELECT id_usuario, nombreCompleto AS nombre_usuario FROM USUARIO ORDER BY nombreCompleto ASC'
    );

    res.render('editar_cotizaciones', {
      cotizacion: c,
      usuarios,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error('Error cargando cotización:', err);
    res.status(500).send('Error en el servidor');
  }
});

app.post('/cotizaciones/editar/:id', estaLogueado, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;

    // Helpers para normalizar
    const toNumOrNull = v =>
      (v === undefined || v === null || String(v).trim() === '')
        ? null
        : Number(v);

    const trimOrNull = v => {
      const s = (v ?? '').trim();
      return s === '' ? null : s;
    };

    const {
      folioVisible,
      fechaDeFolio,
      partidasCotizadas,
      montoMaxCotizado,
      dependencia,
      vigenciaDeLaCotizacion,
      fechaFinDeLaCotizacion,
      estatusDeLaCotizacion,
      partidasAsignadas,
      montoMaximoAsignado,
      responsableDeLaCotizacion
    } = req.body;

    // Calcular vigencia/fecha fin según lo que venga del form
    const { vigencia, fechaFin } = calcularVigenciaYFechaFin(
      fechaDeFolio,
      vigenciaDeLaCotizacion,
      fechaFinDeLaCotizacion
    );

    // Preparar valores
    const folioParaGuardar       = trimOrNull(folioVisible);                 // null si vacío
    const fechaDeFolioSQL        = fechaDeFolio || null;
    const partidasCotizadasSQL   = toNumOrNull(partidasCotizadas);
    const partidasAsignadasSQL   = toNumOrNull(partidasAsignadas);
    const montoMaxCotizadoSQL    = toNumOrNull(montoMaxCotizado);
    const montoMaximoAsignadoSQL = toNumOrNull(montoMaximoAsignado);
    const dependenciaSQL         = trimOrNull(dependencia);
    const responsableFKSQL       = toNumOrNull(responsableDeLaCotizacion);
    const estatusSQL             = estatusDeLaCotizacion || 'pendiente';

    conn = await db.getConnection();
    await conn.beginTransaction();

    // ⚠️ Importante: en edición NO cambiamos el noDeFolio_FKcotizacion
    await conn.query(
      `UPDATE COTIZACION SET
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
        vigencia,                     // puede ser null
        fechaFin,                     // puede ser null (YYYY-MM-DD)
        responsableFKSQL,             // puede ser null
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


// ELIMINAR (si lo usas en el listado)
app.get('/cotizaciones/eliminar/:id', estaLogueado, async (req, res) => {
  try {
    await db.query('DELETE FROM COTIZACION WHERE id_cotizacion = ?', [req.params.id]);
  } catch (err) {
    console.error('Error eliminando cotización:', err);
  } finally {
    res.redirect('/cotizaciones');
  }
});

// ===== Alias opcionales en singular (evita "Cannot GET/POST /cotizacion/*") =====
app.get('/cotizacion/nueva', (req, res) => res.redirect(302, '/cotizaciones/nueva'));
app.post('/cotizacion/nueva', (req, res) => res.redirect(307, '/cotizaciones/nueva'));
app.get('/cotizacion/editar/:id', (req, res) => res.redirect(302, `/cotizaciones/editar/${req.params.id}`));
app.post('/cotizacion/editar/:id', (req, res) => res.redirect(307, `/cotizaciones/editar/${req.params.id}`));

// ======================== PUERTO PARA CONECTARSE CON NODE ========================
const PORT = 3005;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
