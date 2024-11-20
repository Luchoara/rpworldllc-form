<?php
// Habilitar la visualización de errores para facilitar la depuración
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configuración de conexión a la base de datos
$host = 'localhost';  // Dirección del servidor de base de datos
$dbname = 'rpworldllc_form_submissions';  // Nombre de la base de datos
$username = 'rpworldllc_luis';  // Usuario de la base de datos
$password = 'Rpleads321#';  // Contraseña de la base de datos

// Establecer encabezados para respuesta JSON
header('Content-Type: application/json');

try {
    // Crear conexión con PDO
    $conn = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Leer el JSON enviado en el cuerpo de la solicitud POST
    $jsonData = file_get_contents('php://input');
    $data = json_decode($jsonData, true);

    if (!$data) {
        echo json_encode(["status" => "error", "message" => "No se pudo decodificar JSON. Datos recibidos: " . $jsonData]);
        exit();
    }

    // Validar el campo OriginalUrl
    if (empty($data['OriginalUrl'])) {
        echo json_encode(["status" => "error", "message" => "El campo OriginalUrl es obligatorio."]);
        exit();
    }

    // Extraer datos del array $data
    $apiToken = $data['ApiToken'];  // Token estático
    $vertical = 'Medicare';  // Vertical estático
    $originalUrl = $data['OriginalUrl'];
    $publisher_id = $data['publisher_id'];

    // Crear los datos dinámicos en JSON
    $dynamicData = [
        'ContactData' => [
            'FirstName' => $data['first_name'] ?? '',
            'LastName' => $data['last_name'] ?? '',
            'Address' => $data['address'] ?? '',
            'City' => $data['caller_city'] ?? '',
            'State' => $data['caller_state'] ?? '',
            'ZipCode' => $data['caller_zip'] ?? '',
            'EmailAddress' => $data['email'] ?? '',
            'PhoneNumber' => $data['caller_number'] ?? '',
            'IpAddress' => $data['IpAddress'] ?? ''
        ],
        'Person' => [
            'BirthDate' => $data['dob'] ?? '',
            'Gender' => $data['Gender'] ?? '',
            'Product' => $data['Product'] ?? '',
            'RelationshipToApplicant' => $data['RelationshipToApplicant'] ?? '',
            'HouseHoldIncome' => $data['HouseHoldIncome'] ?? '',
            'HouseHoldSize' => $data['HouseHoldSize'] ?? ''
        ],
        "Conditions" => [
            
            "HighCholesterol"=> $data['HighCholesterol'] ?? '',
            "PulmonaryDisease"=> $data['PulmonaryDisease'] ?? '',
            "VascularDisease"=> $data['VascularDisease'] ?? '',
            "AIDSHIV"=> $data['AIDSHIV'] ?? '',
            "KidneyDisease"=> $data['KidneyDisease'] ?? '',
            "Asthma"=> $data['Asthma'] ?? '',
            "Cancer"=> $data['Cancer'] ?? '',
            "Depression"=> $data['Depression'] ?? '',
            "Diabetes"=> $data['Diabetes'] ?? '',
            "HeartDisease"=> $data['HeartDisease'] ?? '',
            "LiverDisease"=> $data['LiverDisease'] ?? '',
            "HighBloodPressure"=> $data['HighBloodPressure'] ?? '',
            "MentalIllness"=> $data['MentalIllness'] ?? '',
            "Stroke"=> $data['Stroke'] ?? '',
            "Alzheimer"=> $data['Alzheimer'] ?? '',
            "AlcoholAbuse"=> $data['AlcoholAbuse'] ?? '',
        ],
        'FirstTimeBuyer' => $data['FirstTimeBuyer'] ?? null,
        'Source' => $data['Source'] ?? null,
        'SessionLength' => $data['SessionLength'] ?? null,
        'TcpaText' => $data['TcpaText'] ?? null
    ];
    $jsonDataToStore = json_encode($dynamicData);

    // Preparar la consulta de inserción
    $sql = "INSERT INTO leadform (publisher_id, ApiToken, Vertical, OriginalUrl, data) VALUES (:publisher_id, :ApiToken, :Vertical, :OriginalUrl, :data)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':publisher_id', $publisher_id, PDO::PARAM_STR);
    $stmt->bindParam(':ApiToken', $apiToken, PDO::PARAM_STR);
    $stmt->bindParam(':Vertical', $vertical, PDO::PARAM_STR);
    $stmt->bindParam(':OriginalUrl', $originalUrl, PDO::PARAM_STR);
    $stmt->bindParam(':data', $jsonDataToStore, PDO::PARAM_STR);

    // Intentar ejecutar la consulta
    if ($stmt->execute()) {
        echo json_encode(["status" => "success", "message" => "Registro exitoso"]);
    } else {
        // Añadir más información en caso de fallo
        $errorInfo = $stmt->errorInfo();
        echo json_encode(["status" => "error", "message" => "No se pudo insertar el registro en leadform", "errorInfo" => $errorInfo]);
    }
} catch (PDOException $e) {
    echo json_encode(["status" => "error", "message" => "Error en la conexión o en la consulta: " . $e->getMessage()]);
} catch (Exception $e) {
    echo json_encode(["status" => "error", "message" => "Ocurrió un error inesperado: " . $e->getMessage()]);
}
?>
