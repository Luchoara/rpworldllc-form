<?php
// Datos de conexión
$host = 'localhost';
$db = 'rpworldllc_form_submissions'; 
$user = 'rpworldllc_luis'; 
$pass = 'Rpleads321#'; // Usando la contraseña correcta

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "Conexión exitosa<br>";

    // Insertar datos de prueba
    $sql = "INSERT INTO test_table (name, email) VALUES ('Juan Perez', 'juan@example.com')";
    $pdo->exec($sql);
    echo "Registro insertado exitosamente<br>";

    // Consultar datos
    $stmt = $pdo->query("SELECT * FROM test_table");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "ID: " . $row['id'] . " - Name: " . $row['name'] . " - Email: " . $row['email'] . "<br>";
    }

} catch (PDOException $e) {
    echo "Error en la conexión: " . $e->getMessage();
}
?>
