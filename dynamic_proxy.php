<?php
// Habilitar la visualización de errores para depuración
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configuración de encabezados para respuesta JSON
header('Content-Type: application/json');

function generateUUIDv4() {
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40); // Version 4
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80); // Variant is 10
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

try {
    // Leer el JSON enviado en el cuerpo de la solicitud POST
    $jsonData = file_get_contents('php://input');
    $data = json_decode($jsonData, true);

    if (!$data) {
        echo json_encode(["status" => "error", "message" => "No se pudo decodificar JSON. Datos recibidos: " . $jsonData]);
        exit();
    }

    // Validar que se hayan recibido los campos principales necesarios
    if (!isset($data['campaign_key'], $data['publisher_id'], $data['caller_number'])) {
        echo json_encode(["status" => "error", "message" => "Faltan datos necesarios", "data" => $data]);
        exit();
    }

    // Definir la URL base
    $baseUrl = 'https://rtb.retreaver.com/rtbs.json';

    // Añadir los parámetros a la URL usando los datos recibidos
    $queryParams = [
        'key' => '96c61c1b-563d-4973-8513-55cade5b289d', // Usando el ejemplo proporcionado
        'publisher_id' => $data['publisher_id'],
        'caller_number' => $data['caller_number'],
        'inbound_number' => isset($data['inbound_number']) ? $data['inbound_number'] : '',
        'caller_state' => isset($data['caller_state']) ? $data['caller_state'] : '',
        'caller_zip' => isset($data['caller_zip']) ? $data['caller_zip'] : ''
    ];

    // Construir la URL con los parámetros de consulta
    $url = $baseUrl . '?' . http_build_query($queryParams);

    // Configurar los encabezados de la solicitud
    $headers = [
        'Content-Type: application/json'
    ];

    // Opciones de contexto para la solicitud HTTP
    $options = [
        'http' => [
            'header'  => implode("\r\n", $headers),
            'method'  => 'POST',
            'content' => $jsonData
        ]
    ];

    $context  = stream_context_create($options);
    $response = @file_get_contents($url, false, $context);

    // Manejar errores en la solicitud
    if ($response === FALSE) {
        $http_response_header = $http_response_header ?? [];
        echo json_encode(["status" => "error", "message" => "Error al enviar la solicitud a la URL remota", "http_response_header" => $http_response_header]);
        exit();
    }

    // Parsear la respuesta y enviarla al cliente
    try {
        $parsedResponse = json_decode($response, true);
        if ($parsedResponse === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Error al parsear la respuesta JSON");
        }
        echo json_encode(["data" => $parsedResponse]);
    } catch (Exception $e) {
        echo json_encode(["status" => "error", "message" => "Error al parsear la respuesta JSON: " . $e->getMessage()]);
    }

} catch (Exception $e) {
    echo json_encode(["status" => "error", "message" => "Ocurrió un error inesperado: " . $e->getMessage()]);
}
?>
