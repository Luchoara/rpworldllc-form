<?php
$host = "localhost";
$usuario = "rpworldllc";
$contrasena = "lGXzG&lKqyqU";
$base_datos = "rpworldllc_database-test";

// Crear la conexión
$conexion = new mysqli($host, $usuario, $contrasena, $base_datos);

// Verificar la conexión
if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}
echo "Conexión exitosa";
?>
