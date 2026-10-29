<?php
const TOKEN = 'test-token-0123456789abcdef0123456789abcdef';

$path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
header('Content-Type: application/json');

if (preg_match('#^/site/(\w+)/wp-json/cube-monitor/v1/report$#', $path, $match)) {
    $file = __DIR__ . "/sites/{$match[1]}.json";
    if (($_SERVER['HTTP_X_CUBE_MONITOR_TOKEN'] ?? '') !== TOKEN || !is_file($file)) {
        http_response_code(404);
        echo '{"code":"rest_no_route"}';
        return;
    }
    echo str_replace('{{NOW}}', gmdate('Y-m-d\TH:i:s\Z'), file_get_contents($file));
    return;
}
if (preg_match('#^/api/(plugin|core|php)/([^/]+)/$#', $path, $match)) {
    $file = __DIR__ . "/api/{$match[1]}/{$match[2]}.json";
    echo is_file($file)
        ? file_get_contents($file)
        : json_encode(['error' => 0, 'message' => null, 'data' => [$match[1] => $match[2], 'vulnerability' => null]]);
    return;
}
if (str_starts_with($path, '/down/')) {
    http_response_code(500);
    echo '{"error":1,"message":"maintenance"}';
    return;
}
http_response_code(404);
echo '{"code":"rest_no_route"}';
