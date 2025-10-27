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

// ------------------------ ENTRADAS ------------------------ 

// GET: Mostrar todas las entradas
app.get('/entradas', estaLogueado, async (req, res) => {
  try {
    const [entrada] = await db.query(`
            SELECT entrada.*, catalogo.nombreProdu_catalogo AS ProductoNombre
            FROM entrada
            INNER JOIN INVENTARIO ON entrada.producto_FKdeInv = INVENTARIO.id_inventario
            INNER JOIN CATALOGO ON INVENTARIO.producto_FKinventario = CATALOGO.id_catalogo
            ORDER BY entrada.fechaDeEntrada DESC
        `);
    res.render('entradas', { entrada, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando entradas:', err);
    res.send('Error cargando entradas');
  }
});


// GET: Mostrar formulario de nueva entrada
app.get('/entradas/nueva', estaLogueado, async (req, res) => {
  try {
    const [productos] = await db.query('SELECT nombreProdu_catalogo, clave_catalogo, id_catalogo FROM CATALOGO');
    res.render('editar_entrada', { productos, usuario: req.session.usuario, editar: false });
  } catch (err) {
    console.error('Error cargando productos:', err);
    res.send('Error cargando productos');
  }
});


/*
// GET: Mostrar formulario de nueva entrada
app.get('/entradas/nueva', estaLogueado, async (req, res) => {
    try {
        const [productos] = await db.query(`
            SELECT id_catalogo, nombreProdu_catalogo FROM CATALOGO
        `);
        res.render('nueva_entrada', { productos, usuario: req.session.usuario });
    } catch (err) {
        console.error('Error cargando productos:', err);
        res.send('Error cargando productos');
    }
});*/


// POST: Guardar nueva entrada
app.post('/entradas/nueva', estaLogueado, async (req, res) => {
    const { Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total } = req.body;

    try {
        // 1️⃣ Validar que el producto exista en el catálogo
        const [[productoExiste]] = await db.query(`
            SELECT * FROM CATALOGO WHERE id_catalogo = ?
        `, [Producto]);

        if (!productoExiste) {
            return res.send("❌ Error: No puedes registrar una entrada de un producto que no está en el catálogo.");
        }

        // 2️⃣ Buscar si ese producto/lote ya existe en inventario
        const [[invExiste]] = await db.query(`
             SELECT COUNT(id_inventario) AS IdInventario, COUNT(id_entrada) AS IdEntrada, id_inventario
             FROM entrada
             INNER JOIN INVENTARIO ON entrada.producto_FKdeInv = INVENTARIO.id_inventario
             WHERE producto_FKinventario = ? AND lote_inventario = ? GROUP BY(id_inventario);
        `, [Producto, Lote]);

        let inventarioId;
        inventarioId = invExiste.id_inventario;
          console.log("Verificando existencia de inventario para producto y lote:", invExiste.IdInventario);
        if (invExiste.IdInventario >= 1) {
          console.log("El inventario ya existe para este producto y lote:", invExiste.IdInventario);

          // 3️⃣ Registrar la entrada (ya con el id del inventario vinculado)
        await db.query(`
            INSERT INTO ENTRADA
            (proveedor, fechaDeEntrada, lote, caducidad, cantidad, costoTotal_entrada, producto_FKdeInv)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [Proveedor, Fecha_de_entrada, Lote, Caducidad, Cantidad, Costo_Total, inventarioId]);

            // Si ya existe, actualizar stock
            await db.query(`
                UPDATE INVENTARIO
                SET stock_inventario = stock_inventario + ?,
                    caducidad_inventario = ?,
                    diasRestantes_inventario = DATEDIFF(?, CURDATE()),
                    estadoDelProducto_inventario = 'Disponible'
                WHERE id_inventario = ?
            `, [Cantidad, Caducidad, Caducidad, inventarioId]);
            console.log('✅ Inventario actualizado:', req.body);
        } else if (invExiste.IdInventario == 0 || invExiste.IdInventario == null) {
          console.log("El inventario no existe para este producto y lote. Creando nuevo inventario.", invExiste.IdInventario);
          await db.query(`
            INSERT INTO ENTRADA
            (proveedor, fechaDeEntrada, lote, caducidad, cantidad, costoTotal_entrada, producto_FKdeInv)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [Proveedor, Fecha_de_entrada, Lote, Caducidad, Cantidad, Costo_Total, inventarioId]);
            // Si no existe, crear inventario vinculado a catálogo
            const [nuevoInv] = await db.query(`
                INSERT INTO INVENTARIO
                (producto_FKinventario, lote_inventario, stock_inventario, caducidad_inventario, diasRestantes_inventario, estadoDelProducto_inventario)
                VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible')
            `, [Producto, Lote, Cantidad, Caducidad, Caducidad]);
            //inventarioId = nuevoInv.insertId;
            console.log('✅ Nueva entrada registrada en inventario:', req.body);
        }


        res.redirect('/entradas');
    } catch (err) {
        console.error('Error al agregar entrada:', err);
        res.send('Error al agregar entrada');
    }
});


// GET: Formulario para editar entrada
app.get('/entradas/editar/:id', estaLogueado, async (req, res) => {
  const entradaId = req.params.id;
  try {
    const [[entrada]] = await db.query('SELECT * FROM entrada WHERE id_entrada = ?', [entradaId]);
    if (!entrada) return res.send('Entrada no encontrada');

    const [productos] = await db.query('SELECT nombreProdu_catalogo, clave_catalogo, id_catalogo FROM CATALOGO');

    res.render('editar_entrada', {
      productos,
      entrada,
      usuario: req.session.usuario,
      editar: true
    });
  } catch (err) {
    console.error('Error cargando entrada para editar:', err);
    res.send('Error cargando entrada');
  }
});


// POST: Procesar edición de entrada
app.post('/entradas/editar/:id', estaLogueado, async (req, res) => {
    const entradaId = req.params.id;
    const { Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total } = req.body;

    try {
        // Validar existencia en catálogo
        const [[productoExiste]] = await db.query('SELECT * FROM CATALOGO WHERE id_catalogo = ?', [Producto]);
        if (!productoExiste) return res.send('❌ Error: El producto no existe en el catálogo.');

        // Obtener entrada anterior
        const [[entradaAnterior]] = await db.query('SELECT * FROM ENTRADA WHERE id_entrada = ?', [entradaId]);
        if (!entradaAnterior) return res.send('Entrada original no encontrada');

        // Restar stock anterior
        await db.query(`
            UPDATE INVENTARIO
            SET stock_inventario = stock_inventario - ?
            WHERE id_inventario = ?
        `, [entradaAnterior.cantidad, entradaAnterior.producto_FKdeInv]);

        // Verificar si existe inventario para el nuevo producto/lote
        const [[invNuevo]] = await db.query(`
            SELECT id_inventario FROM INVENTARIO
            WHERE producto_FKinventario = ? AND lote_inventario = ?
        `, [Producto, Lote]);

        let inventarioId = invNuevo?.id_inventario;

        if (invNuevo) {
            // Actualizar stock existente
            await db.query(`
                UPDATE INVENTARIO
                SET stock_inventario = stock_inventario + ?,
                    caducidad_inventario = ?,
                    diasRestantes_inventario = DATEDIFF(?, CURDATE())
                WHERE id_inventario = ?
            `, [Cantidad, Caducidad, Caducidad, inventarioId]);
        } else {
            // Crear inventario nuevo vinculado a catálogo
            const [nuevoInv] = await db.query(`
                INSERT INTO INVENTARIO
                (producto_FKinventario, lote_inventario, stock_inventario, caducidad_inventario, diasRestantes_inventario, estadoDelProducto_inventario)
                VALUES (?, ?, ?, ?, DATEDIFF(?, CURDATE()), 'Disponible')
            `, [Producto, Lote, Cantidad, Caducidad, Caducidad]);
            inventarioId = nuevoInv.insertId;
        }

        // Actualizar entrada
        await db.query(`
            UPDATE ENTRADA
            SET proveedor = ?, fechaDeEntrada = ?, lote = ?, caducidad = ?, cantidad = ?, costoTotal_entrada = ?, producto_FKdeInv = ?
            WHERE id_entrada = ?
        `, [Proveedor, Fecha_de_entrada, Lote, Caducidad, Cantidad, Costo_Total, inventarioId, entradaId]);

        console.log('✅ Entrada editada correctamente');
        res.redirect('/entradas');
    } catch (err) {
        console.error('Error editando entrada:', err);
        res.send('Error editando entrada');
    }
});


/*
// GET: Formulario para editar entrada
app.get('/entradas/editar/:id', estaLogueado, async (req, res) => {
  const entradaId = req.params.id;
  try {
    const [[entrada]] = await db.query('SELECT * FROM entrada WHERE id_entrada = ?', [entradaId]);
    if (!entrada) return res.send('Entrada no encontrada');

    const [productos] = await db.query('SELECT nombreProdu_catalogo, clave_catalogo, id_catalogo FROM CATALOGO');

    res.render('editar_entrada', {
      productos,
      entrada,
      usuario: req.session.usuario,
      editar: true
    });
  } catch (err) {
    console.error('Error cargando entrada para editar:', err);
    res.send('Error cargando entrada');
  }
});


// POST: Procesar edición de entrada
app.post('/entradas/editar/:id', estaLogueado, async (req, res) => {
  const entradaId = req.params.id;
  console.log('Entrada ID a editar:', entradaId);
  const { Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total } = req.body;

  try {
    // Obtener entrada anterior



    // Actualizar entrada
    const [resEntrada] = await db.query(`
      
            UPDATE entrada
            SET fechaDeEntrada = ?, proveedor = ?, producto_FKdeInv = ?, lote = ?, caducidad = ?, cantidad = ?, costoTotal_entrada = ?
            WHERE id_entrada = ?;
        `, [Fecha_de_entrada, Proveedor, Producto, Lote, Caducidad, Cantidad, Costo_Total, entradaId]);

    console.log('Aqui vas', req.body);

    console.log('Resultado UPDATE entrada:', resEntrada);


    const [[entradaAnterior]] = await db.query('SELECT entrada.*, inventario.id_inventario FROM entrada INNER JOIN INVENTARIO ON entrada.producto_FKdeInv = INVENTARIO.id_inventario WHERE id_entrada = ?', [entradaId]);
    if (!entradaAnterior) return res.send('Entrada original no encontrada');
    console.log('Aqui vas 2', entradaAnterior);
    // Ajustar inventario: restar cantidad anterior
    const [resInventario] = await db.query(`
            UPDATE inventario
            SET stock_inventario = stock_inventario - ?, caducidad_inventario = ?, diasRestantes_inventario = DATEDIFF(?, CURDATE())
            WHERE id_inventario = ? AND lote_inventario = ?;
        `, [entradaAnterior.cantidad, entradaAnterior.caducidad, entradaAnterior.caducidad, entradaAnterior.id_inventario, entradaAnterior.lote]);

    console.log('Aqui vas 3', entradaAnterior);

    console.log('Resultado UPDATE inventario:', resInventario);
    
    // Ajustar inventario: sumar nueva cantidad
    await db.query(`
             UPDATE inventario
             SET stock_inventario = stock_inventario + ?, caducidad_inventario = ?, diasRestantes_inventario = DATEDIFF(?, CURDATE())
             WHERE id inventario = ? AND lote_inventario = ?;
         `, [Cantidad, Caducidad, Caducidad, Producto, Lote]);

    console.log('Entrada editada:', req.body);
    res.redirect('/entradas');
  } catch (err) {
    console.error('Error editando entrada:', err);
    res.send('Error editando entrada');
  }
});*/


// ========================= SALIDAS =========================

// GET: Mostrar todas las salidas con nombres de cliente y producto
app.get('/salidas', estaLogueado, async (req, res) => {
  try {
    const [salidas] = await db.query(`
            SELECT s.*, cl.Nombre AS ClienteNombre, ca.Nombre AS ProductoNombre
            FROM salidas s
            JOIN clientes cl ON s.ClienteId = cl.Id
            JOIN catalogo ca ON s.Producto = ca.Codigo
            ORDER BY s.Fecha DESC
        `);
    res.render('salidas', { salidas, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando salidas:', err);
    res.send('Error cargando salidas');
  }
});

// GET: Buscar salida por orden de compra
app.get('/salidas/buscar', estaLogueado, async (req, res) => {
  const orden = parseInt(req.query.orden_buscar, 10);
  if (isNaN(orden)) return res.redirect('/salidas');

  try {
    const [salidas] = await db.query(`
            SELECT s.*, cl.Nombre AS ClienteNombre, ca.Nombre AS ProductoNombre
            FROM salidas s
            JOIN clientes cl ON s.ClienteId = cl.Id
            JOIN catalogo ca ON s.Producto = ca.Codigo
            WHERE s.orden_de_compra = ?
            ORDER BY s.Fecha DESC
        `, [orden]);
    res.render('salidas', { salidas, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error buscando orden de compra:', err);
    res.send('Error buscando orden de compra');
  }
});

// GET: Formulario para nueva salida
app.get('/salidas/nueva', estaLogueado, async (req, res) => {
  try {
    const [clientes] = await db.query('SELECT * FROM clientes');
    const [productos] = await db.query('SELECT * FROM catalogo');
    const [lotes] = await db.query(`
            SELECT Producto, Lote, Caducidad, Stock 
            FROM inventario 
            WHERE Stock > 0
        `);
    res.render('nueva_salida', { clientes, productos, lotes, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando formulario de nueva salida:', err);
    res.send('Error cargando formulario de nueva salida');
  }
});

// POST: Procesar nueva salida y actualizar inventario
app.post('/salidas/nueva', estaLogueado, async (req, res) => {
  try {
    let { Fecha, ClienteId, Producto, Lote, Cantidad, Precio_Venta, Total_Facturado, orden_de_compra, Folio_de_Facturacion } = req.body;
    const cantidadNum = parseInt(Cantidad, 10);

    // Verificar stock y caducidad del lote
    const [inventarioRes] = await db.query(
      'SELECT Stock, Caducidad FROM inventario WHERE Producto = ? AND Lote = ?',
      [Producto, Lote]
    );

    if (inventarioRes.length === 0 || inventarioRes[0].Stock < cantidadNum) {
      return res.send(`
                <h2 style="color:red;">Error: Stock insuficiente o lote inexistente</h2>
                <a href="/salidas/nueva"><button>Volver</button></a>
            `);
    }

    const caducidad = inventarioRes[0].Caducidad;

    const usarSecuencia = !orden_de_compra || orden_de_compra === '';

    const insertarSalida = async (ordenOC) => {
      await db.query(`
                INSERT INTO salidas
                (Fecha, ClienteId, Producto, Lote, Cantidad, Precio_Venta, Total_Facturado, orden_de_compra, Caducidad, Folio_de_Facturacion)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [Fecha, ClienteId, Producto, Lote, cantidadNum, Precio_Venta, Total_Facturado, ordenOC, caducidad, Folio_de_Facturacion || null]);

      // Actualizar inventario
      await db.query(`
                UPDATE inventario
                SET Stock = Stock - ?, Dias_Restantes_a_Caducar = DATEDIFF(Caducidad, CURDATE())
                WHERE Producto = ? AND Lote = ?
            `, [cantidadNum, Producto, Lote]);

      // Eliminar fila si stock llega a 0
      await db.query('DELETE FROM inventario WHERE Producto = ? AND Lote = ? AND Stock <= 0', [Producto, Lote]);

      res.redirect('/salidas');
    };

    if (usarSecuencia) {
      const [[ocRes]] = await db.query(
        "SELECT ultimo_valor + 1 AS siguiente FROM consecutivos WHERE nombre = 'orden_de_compra' FOR UPDATE"
      );
      const siguienteOC = ocRes.siguiente;
      await db.query("UPDATE consecutivos SET ultimo_valor = ? WHERE nombre = 'orden_de_compra'", [siguienteOC]);
      await insertarSalida(siguienteOC);
    } else {
      await insertarSalida(parseInt(orden_de_compra, 10));
    }
  } catch (err) {
    console.error('Error procesando nueva salida:', err);
    res.send('Error procesando nueva salida');
  }
});

// GET: Formulario para editar salida
app.get('/salidas/editar/:id', estaLogueado, async (req, res) => {
  const salidaId = req.params.id;
  try {
    const [[salida]] = await db.query('SELECT * FROM salidas WHERE Id = ?', [salidaId]);
    if (!salida) return res.send('Salida no encontrada');

    const [clientes] = await db.query('SELECT * FROM clientes');
    const [productos] = await db.query('SELECT * FROM catalogo');
    const [lotes] = await db.query(`
            SELECT Producto, Lote, Caducidad, Stock
            FROM inventario
            WHERE Stock > 0
            UNION
            SELECT Producto, Lote, Caducidad, 0 AS Stock
            FROM salidas
            WHERE Id = ?
        `, [salidaId]);

    res.render('editar_salida', { salida, clientes, productos, lotes, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando salida para editar:', err);
    res.send('Error cargando salida para editar');
  }
});

// POST: Procesar edición de salida
app.post('/salidas/editar/:id', estaLogueado, async (req, res) => {
  const salidaId = req.params.id;
  try {
    const { Fecha, ClienteId, Producto, Lote, Cantidad, Precio_Venta, Total_Facturado, orden_de_compra, Folio_de_Facturacion } = req.body;
    const cantidadNum = parseInt(Cantidad, 10);
    const nuevaOrden = parseInt(orden_de_compra, 10);

    const [[original]] = await db.query('SELECT * FROM salidas WHERE Id = ?', [salidaId]);
    if (!original) return res.send('Salida original no encontrada');

    const diferencia = cantidadNum - original.Cantidad;

    // Actualizar inventario según la diferencia
    await db.query('UPDATE inventario SET Stock = Stock - ? WHERE Producto = ? AND Lote = ?', [diferencia, Producto, Lote]);

    // Verificar stock disponible después del ajuste
    const [invRes] = await db.query('SELECT Stock FROM inventario WHERE Producto = ? AND Lote = ?', [Producto, Lote]);
    const stockDisponible = invRes.length > 0 ? invRes[0].Stock : 0;
    if (stockDisponible < 0) {
      return res.send(`
                <h2 style="color:red;">Error: Stock insuficiente en lote seleccionado</h2>
                <a href="/salidas"><button class="btn">Volver</button></a>
            `);
    }

    // Actualizar la salida
    await db.query(`
            UPDATE salidas
            SET Fecha = ?, ClienteId = ?, Producto = ?, Lote = ?, Cantidad = ?, Precio_Venta = ?, Total_Facturado = ?, orden_de_compra = ?, Folio_de_Facturacion = ?
            WHERE Id = ?
        `, [Fecha, ClienteId, Producto, Lote, cantidadNum, Precio_Venta, Total_Facturado, nuevaOrden, Folio_de_Facturacion, salidaId]);

    // Eliminar fila de inventario si stock llega a 0
    await db.query('DELETE FROM inventario WHERE Producto = ? AND Lote = ? AND Stock <= 0', [Producto, Lote]);

    res.redirect('/salidas');
  } catch (err) {
    console.error('Error editando salida:', err);
    res.send('Error editando salida');
  }
});

// ========================= INVENTARIO =========================

// GET: Mostrar inventario
app.get('/inventario', estaLogueado, async (req, res) => {
  try {
    const [inventario] = await db.query(`
            SELECT i.*, c.Nombre AS ProductoNombre 
            FROM inventario i
            JOIN catalogo c ON i.Producto = c.Codigo
            ORDER BY i.Caducidad ASC
        `);
    res.render('inventario', { inventario, usuario: req.session.usuario });
  } catch (err) {
    console.error('Error cargando inventario:', err);
    res.send('Error cargando inventario');
  }
});

// ------------------------ CLIENTES ------------------------
// Mostrar todos los clientes
app.get('/clientes', estaLogueado, async (req, res) => {
  try {
    const [resultados] = await db.query('SELECT * FROM clientes');
    res.render('clientes', {
      clientes: resultados,
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error(err);
    res.send('Error cargando clientes');
  }
});

// Mostrar formulario para agregar cliente
app.get('/clientes/nuevo', estaLogueado, (req, res) => {
  res.render('agregar_cliente', {
    usuario: req.session.usuario
  });
});

// Procesar nuevo cliente
app.post('/clientes/agregar', async (req, res) => {
  const { Nombre, RFC, Direccion, Telefono, Correo } = req.body;
  const sql = 'INSERT INTO clientes (Nombre, RFC, Direccion, Telefono, Correo) VALUES (?, ?, ?, ?, ?)';

  try {
    await db.query(sql, [Nombre, RFC, Direccion, Telefono, Correo]);
    res.redirect('/clientes');
  } catch (err) {
    console.error(err);
    res.send('Error al agregar cliente');
  }
});

// Mostrar formulario para editar cliente
app.get('/clientes/editar/:id', estaLogueado, async (req, res) => {
  const clienteId = req.params.id;

  try {
    const [resultados] = await db.query('SELECT * FROM clientes WHERE Id = ?', [clienteId]);

    if (resultados.length === 0) {
      return res.send('Cliente no encontrado');
    }

    res.render('editar_cliente', {
      cliente: resultados[0],
      usuario: req.session.usuario
    });
  } catch (err) {
    console.error(err);
    res.send('Error al cargar cliente');
  }
});

// Procesar edición de cliente y actualizar salidas
app.post('/clientes/editar/:id', async (req, res) => {
  const clienteId = req.params.id;
  const { Nombre, RFC, Direccion, Telefono, Correo } = req.body;

  const sqlUpdateCliente = `
    UPDATE clientes 
    SET Nombre = ?, RFC = ?, Direccion = ?, Telefono = ?, Correo = ? 
    WHERE Id = ?
  `;

  try {
    await db.query(sqlUpdateCliente, [Nombre, RFC, Direccion, Telefono, Correo, clienteId]);

    // Actualizar también salidas (opcional)
    const sqlUpdateSalidas = `
      UPDATE salidas 
      SET ClienteNombre = ?
      WHERE ClienteId = ?
    `;
    await db.query(sqlUpdateSalidas, [Nombre, clienteId]);

    res.redirect('/clientes');
  } catch (err) {
    console.error('Error al actualizar cliente:', err);
    res.send('Error al actualizar cliente');
  }
});

// Eliminar cliente
app.post('/clientes/eliminar/:id', async (req, res) => {
  const clienteId = req.params.id;

  try {
    await db.query('DELETE FROM clientes WHERE Id = ?', [clienteId]);
    res.redirect('/clientes');
  } catch (err) {
    console.error('Error eliminando cliente:', err);
    res.send('Error al eliminar cliente');
  }
});

// ------------------------ COTIZACIONES ------------------------

app.get('/cotizaciones', estaLogueado, async (req, res) => {
  try {
    const [cotizaciones] = await db.query('SELECT * FROM cotizaciones');
    res.render('cotizaciones', {
      usuario: req.session.usuario,
      cotizaciones
    });
  } catch (err) {
    console.error('Error cargando cotizaciones:', err);
    res.status(500).send('Error en el servidor');
  }
});

// ---------- FORMULARIO NUEVA COTIZACIÓN ----------
app.get('/cotizaciones/nueva', estaLogueado, (req, res) => {
  res.render('editar_cotizaciones', { cotizacion: null });
});

// ---------- GUARDAR NUEVA COTIZACIÓN ----------
app.post('/cotizaciones/nueva', estaLogueado, async (req, res) => {
  try {
    const {
      noDeFolio,
      fechaDeFolio,
      partidasCotizadas,
      montoMaxCotizado,
      dependencia,
      vigenciaDeLaCotizacion,
      fechaFinDeLaCotizacion,
      responsableDeLaCotizacion,
      estatusDeLaCotizacion,
      partidasAsignadas,
      montoMaximoAsignado
    } = req.body;

    // --- Cálculos automáticos entre fechaFin y vigencia ---
    let vigencia1 = vigenciaDeLaCotizacion;
    let fechaFin1 = fechaFinDeLaCotizacion;

    if (fechaFinDeLaCotizacion && !vigenciaDeLaCotizacion) {
      // Si hay fecha fin pero no vigencia → calcular vigencia
      const inicio = new Date(fechaDeFolio);
      const fin = new Date(fechaFinDeLaCotizacion);
      vigencia1 = Math.round((fin - inicio) / (1000 * 60 * 60 * 24));
    } else if (!fechaFinDeLaCotizacion && vigenciaDeLaCotizacion) {
      // Si hay vigencia pero no fecha fin → calcular fecha fin
      const inicio = new Date(fechaDeFolio);
      inicio.setDate(inicio.getDate() + parseInt(vigenciaDeLaCotizacion));
      fechaFin1 = inicio.toISOString().split('T')[0];
    }

    await db.query(
      `INSERT INTO cotizaciones 
            (noDeFolio, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia, vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, responsableDeLaCotizacion, estatusDeLaCotizacion, partidasAsignadas, montoMaximoAsignado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [noDeFolio, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia, vigencia1, fechaFin1, responsableDeLaCotizacion, estatusDeLaCotizacion, partidasAsignadas, montoMaximoAsignado]
    );

    res.redirect('/cotizaciones');
  } catch (err) {
    console.error('Error guardando cotización:', err);
    res.status(500).send('Error al guardar la cotización');
  }
});


// ---------- ACTUALIZAR COTIZACIÓN ----------
app.post('/cotizaciones/nueva', estaLogueado, async (req, res) => {
  try {
    const {
      noDeFolio,
      fechaDeFolio,
      partidasCotizadas,
      montoMaxCotizado,
      dependencia,
      vigenciaDeLaCotizacion,
      fechaFinDeLaCotizacion,
      responsableDeLaCotizacion,
      estatusDeLaCotizacion,
      partidasAsignadas,
      montoMaximoAsignado
    } = req.body;

    // -------------------------
    // Manejo de fechas y vigencia
    // -------------------------

    // Convertimos valores vacíos a null
    let vigencia = vigenciaDeLaCotizacion && vigenciaDeLaCotizacion.trim() !== ''
      ? parseInt(vigenciaDeLaCotizacion)
      : null;

    let fechaFin = fechaFinDeLaCotizacion && fechaFinDeLaCotizacion.trim() !== ''
      ? fechaFinDeLaCotizacion
      : null;

    // Si hay vigencia pero no fechaFin, calculamos fechaFin
    if (vigencia && !fechaFin) {
      const inicio = new Date(fechaDeFolio);
      const fin = new Date(inicio);
      fin.setDate(inicio.getDate() + vigencia);
      fechaFin = fin.toISOString().split('T')[0];
    }

    // Si hay fechaFin pero no vigencia, calculamos vigencia en días
    if (fechaFin && !vigencia) {
      const inicio = new Date(fechaDeFolio);
      const fin = new Date(fechaFin);
      const dias = Math.round((fin - inicio) / (1000 * 60 * 60 * 24));
      vigencia = dias;
    }

    // Si no hay ninguno, ambos quedan null
    if (!fechaFin && !vigencia) {
      fechaFin = null;
      vigencia = null;
    }

    // -------------------------
    // Insert en base de datos
    // -------------------------
    await db.query(
      `INSERT INTO cotizaciones
        (noDeFolio, fechaDeFolio, partidasCotizadas, montoMaxCotizado, dependencia, vigenciaDeLaCotizacion, fechaFinDeLaCotizacion, responsableDeLaCotizacion, estatusDeLaCotizacion, partidasAsignadas, montoMaximoAsignado)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        noDeFolio,
        fechaDeFolio,
        partidasCotizadas,
        montoMaxCotizado,
        dependencia,
        vigencia,   // número de días o null
        fechaFin,   // fecha o null
        responsableDeLaCotizacion,
        estatusDeLaCotizacion,
        partidasAsignadas,
        montoMaximoAsignado
      ]
    );

    res.redirect('/cotizaciones');

  } catch (err) {
    console.error('Error guardando cotización:', err);
    res.status(500).send('Error al guardar la cotización');
  }
});

// ======================== PUERTO PARA CONECTARSE CON NODE ========================
const PORT = 3005;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
