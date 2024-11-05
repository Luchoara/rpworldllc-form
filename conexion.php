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

    // Verificar si se recibe la solicitud POST
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // Extraer datos del formulario
        $publisher_id = $_POST['publisher_id'];
        $caller_number = $_POST['caller_number'];
        $first_name = $_POST['first_name'];
        $last_name = $_POST['last_name'];
        $caller_zip = $_POST['caller_zip'];
        $caller_state = $_POST['caller_state'];
        $trusted_form_cert_url = $_POST['trusted_form_cert_url'];

        // Preparar la consulta para insertar los datos en form_data
        $sql = "INSERT INTO form_data (publisher_id, caller_number, first_name, last_name, caller_zip, caller_state, trusted_form_cert_url) 
                VALUES (:publisher_id, :caller_number, :first_name, :last_name, :caller_zip, :caller_state, :trusted_form_cert_url)";

        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':publisher_id', $publisher_id);
        $stmt->bindParam(':caller_number', $caller_number);
        $stmt->bindParam(':first_name', $first_name);
        $stmt->bindParam(':last_name', $last_name);
        $stmt->bindParam(':caller_zip', $caller_zip);
        $stmt->bindParam(':caller_state', $caller_state);
        $stmt->bindParam(':trusted_form_cert_url', $trusted_form_cert_url);
        
        // Ejecutar la consulta
        if ($stmt->execute()) {
            echo "Registro insertado exitosamente en form_data<br>";
        } else {
            echo "Error al insertar el registro: " . implode(", ", $stmt->errorInfo()) . "<br>";
        }
    }
} catch (PDOException $e) {
    echo "Error en la conexión: " . $e->getMessage();
}
?>
