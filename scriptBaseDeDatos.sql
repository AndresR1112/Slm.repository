CREATE DATABASE jartnash_programa CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE jartnash_programa;

CREATE TABLE CATALOGO (
    id_catalogo INT PRIMARY KEY auto_increment,
    clave_catalogo VARCHAR(45),
    claveSSA_catalogo VARCHAR(45),
    nombreProdu_catalogo VARCHAR(45),
    presentacion_catalogo VARCHAR(100),
    precioVenta_catalogo DECIMAL(10,2),
    costoUnitario_catalogo DECIMAL(10,2)
);

CREATE TABLE INVENTARIO (
    id_inventario INT PRIMARY KEY auto_increment,
    producto_FKinventario INT,
    lote_inventario VARCHAR(45),
    stock_inventario INT,
    caducidad_inventario DATE,
    diasRestantes_inventario VARCHAR(45),
    estadoDelProducto_inventario VARCHAR(45),
    
        FOREIGN KEY (producto_FKinventario)
        REFERENCES CATALOGO(id_catalogo)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE ENTRADA (
    id_entrada INT PRIMARY KEY auto_increment,
    proveedor VARCHAR(45),
    fechaDeEntrada DATE,
    lote VARCHAR(45),
    caducidad DATE,
    cantidad INT,
    costoTotal_entrada DECIMAL(10,2),
    producto_FKdeInv INT,
		
        FOREIGN KEY (producto_FKdeInv)
        REFERENCES INVENTARIO(id_inventario)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);



CREATE TABLE CLIENTE (
    id_cliente INT PRIMARY KEY auto_increment,
    nombre_cliente VARCHAR(45),
    RFC_cliente VARCHAR(13) UNIQUE NOT NULL,
    direccion_cliente VARCHAR(250),
    telefono_cliente INT UNIQUE, 
    correo_cliente VARCHAR(45) UNIQUE
);

CREATE TABLE SALIDA (
    id_salida INT PRIMARY KEY auto_increment,
    ordenDeCompra_salida VARCHAR(45),
    fecha_salida DATE,
    id_cliente INT,
    id_inventario INT,
    lote VARCHAR(45),
    cantidad INT,
    precioDeVenta_salida DECIMAL(10,2),
    totalFacturado_salida DECIMAL(10,2),
    folioDeFacturacion_salida VARCHAR(45),
    
    
        FOREIGN KEY (id_inventario)
        REFERENCES INVENTARIO(id_inventario)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    
        FOREIGN KEY (id_cliente)
        REFERENCES CLIENTE(id_cliente)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE USUARIO (
    id_usuario INT PRIMARY KEY auto_increment,
    userName VARCHAR(45) UNIQUE,
    nombreCompleto VARCHAR(45) ,
    tipo_usuario VARCHAR(45),
    telefono_usuario INT(10) UNIQUE,
    correo_usuario VARCHAR(45) UNIQUE,
    contraseña_usuario VARCHAR(255),
    fechaRegistro_usuario DATE
);

CREATE TABLE CONSECUTIVO (
    id_consecutivo INT PRIMARY KEY auto_increment,
    nombre VARCHAR(50),
    ultimoValor INT NOT NULL
);

USE jartnash_programa;
CREATE TABLE COTIZACION (
    id_cotizacion INT PRIMARY KEY auto_increment,
    noDeFolio_FKcotizacion INT,
    fechaDeFolio_cotizacion DATE,
	partidasCotizadas_cotizacion INT,
    montoMaxCotizado_cotizacion DECIMAL(10,2),
    dependencia_cotizacion VARCHAR(45),
    vigenciaDeLaCotizacion INT,
    fechaFinDeLaCotizacion DATE,
    responsableDeLaCotizacionFK INT,
    estatus_cotizacion ENUM('aprobada','pendiente','rechazada')DEFAULT 'pendiente',
    partidasAsignadas_cotizacion INT,
    montoMaxAsignado_cotizacion DECIMAL(10,2),
    
        FOREIGN KEY (responsableDeLaCotizacionFK)
        REFERENCES USUARIO(id_usuario)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    
        FOREIGN KEY (noDeFolio_FKcotizacion)
        REFERENCES CONSECUTIVO(id_consecutivo)
        ON UPDATE CASCADE
        ON DELETE CASCADE
        
		/*
        POSIBLES FUTURAS LLAVES FORANEAS
        FOREIGN KEY (id_catalogo)
        REFERENCES CATALOGO(id_catalogo)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    
        FOREIGN KEY (id_cliente)
        REFERENCES CLIENTE(id_cliente)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,*/
    
);
