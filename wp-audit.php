<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

const API_DEFAULT = 'https://www.wpvulnerability.net';
const USER_AGENT = 'cubesystems/wp-audit';
const JSON_FILE = 'wp-audit.json';
const TIMEOUT_SECONDS = 30;
const DAY_SECONDS = 86400;
const STALE_DATA_DAYS = 2;
const CRON_OVERDUE_MINUTES = 60;
const PHP_SUPPORT_ENDED = 'd';
const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_VULNERABLE = 2;
const SEVERITY_RANK = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'none' => 0, 'unknown' => -1];
const SEVERITY_LETTERS = ['c' => 'critical', 'h' => 'high', 'm' => 'medium', 'l' => 'low', 'n' => 'none'];

$url = rtrim((string) getenv('WP_AUDIT_URL'), '/');
$token = (string) getenv('WP_AUDIT_TOKEN');
$api = rtrim((string) getenv('WP_AUDIT_API') ?: API_DEFAULT, '/');
$missing = array_keys(array_filter(['WP_AUDIT_URL' => $url, 'WP_AUDIT_TOKEN' => $token], fn($value) => $value === ''));
if ($missing) {
    fail(implode(' and ', $missing) . ' not set - CI/CD variable missing, protected on an unprotected branch, or scoped to another environment');
}

[$status, $body] = http_get("$url/wp-json/cube-monitor/v1/report", "X-Cube-Monitor-Token: $token\r\nAccept: application/json\r\n");
$report = $status === 200 ? json_decode($body, true) : null;
if (!is_array($report) || !isset($report['plugins'], $report['core']['version'], $report['php'])) {
    $hint = [0 => 'site unreachable', 401 => 'token rejected or REST blocked', 404 => 'cube-monitor missing or token not set on the server'][$status] ?? 'unexpected response';
    fail("Report failed: HTTP $status ($hint) from $url");
}

$updates = [];
$warnings = [];
$unknown = [];

$phpVersion = numeric_version((string) $report['php']);
$phpData = lookup($api, 'php/' . rawurlencode($phpVersion));
$php = [
    'version'         => $phpVersion,
    'supported'       => ($phpData['status'] ?? null) !== PHP_SUPPORT_ENDED,
    'support_until'   => $phpData['date_end'] ?? null,
    'vulnerabilities' => matching($phpData['vulnerability'] ?? null, $phpVersion),
];
$phpBranch = implode('.', array_slice(explode('.', $phpVersion), 0, 2));
$phpSupport = rtrim(($php['supported'] ? "PHP $phpBranch supported until " : "PHP $phpBranch support ended ") . $php['support_until']);

$coreVersion = (string) $report['core']['version'];
$coreData = lookup($api, 'core/' . rawurlencode($coreVersion));
$wordpress = [
    'version'         => $coreVersion,
    'latest'          => $report['core']['latest'] ?? null,
    'vulnerabilities' => matching($coreData['vulnerability'] ?? null, $coreVersion),
];
if ($wordpress['latest'] !== null && version_compare($wordpress['latest'], $coreVersion, '>')) {
    $updates[] = "WordPress $coreVersion → {$wordpress['latest']}";
}

$plugins = [];
foreach ($report['plugins'] as $entry) {
    $slug = $entry['slug'] ?? plugin_slug((string) $entry['file']);
    $data = lookup($api, 'plugin/' . rawurlencode($slug));
    $plugin = [
        'file'            => $entry['file'],
        'slug'            => $slug,
        'name'            => $entry['name'],
        'version'         => $entry['version'],
        'latest'          => $entry['latest'] ?? null,
        'active'          => (bool) $entry['active'],
        'vulnerabilities' => matching($data['vulnerability'] ?? null, (string) $entry['version']),
    ];
    $label = $entry['name'] . ($entry['active'] ? '' : ' (inactive)');
    if ($plugin['latest'] === null) {
        $plugin['latest_unknown'] = $entry['latest_unknown'] ?? 'unknown';
        $unknown[] = "$label {$entry['version']}: {$plugin['latest_unknown']}";
    } elseif (version_compare($plugin['latest'], $entry['version'], '>')) {
        $seen = isset($entry['seen_at']) ? ' (seen ' . substr($entry['seen_at'], 0, 10) . ')' : '';
        $updates[] = "$label {$entry['version']} → {$plugin['latest']}$seen";
    }
    $plugins[] = $plugin;
}

$checkedAt = $report['core']['checked_at'] ?? null;
$age = $checkedAt ? (int) floor((time() - strtotime($checkedAt)) / DAY_SECONDS) : null;
if ($age === null || $age > STALE_DATA_DAYS) {
    $warnings[] = 'Update data is ' . ($age === null ? 'missing' : "$age days old") . ' - can the server reach api.wordpress.org?';
}
if (($report['env'] ?? null) === 'production') {
    $flags = $report['flags'] ?? [];
    if (empty($flags['DISALLOW_FILE_MODS'])) {
        $warnings[] = 'DISALLOW_FILE_MODS is off - plugins can be changed outside git';
    }
    if (!empty($flags['WP_DEBUG_DISPLAY'])) {
        $warnings[] = 'WP_DEBUG_DISPLAY is on - errors are shown to visitors';
    }
    if (empty($flags['blog_public'])) {
        $warnings[] = 'blog_public is off - the site asks search engines not to index it';
    }
    if (($flags['cron_overdue_min'] ?? 0) > CRON_OVERDUE_MINUTES) {
        $warnings[] = "Cron is {$flags['cron_overdue_min']} min overdue - is the server cron running?";
    }
}

$findings = [["PHP $phpVersion", $php['vulnerabilities']], ["WordPress $coreVersion", $wordpress['vulnerabilities']]];
foreach ($plugins as $plugin) {
    $findings[] = [$plugin['name'] . ($plugin['active'] ? '' : ' (inactive)') . " {$plugin['version']}", $plugin['vulnerabilities']];
}
$total = array_sum(array_map(fn($finding) => count($finding[1]), $findings));

echo "{$report['site']} ({$report['env']}) · WordPress $coreVersion · PHP {$report['php']} · checked " . ($checkedAt ?? 'never') . "\n\n";
if ($total === 0) {
    echo "No known vulnerabilities.\n";
} else {
    echo "Vulnerabilities ($total)\n";
    foreach ($findings as [$name, $vulnerabilities]) {
        if (!$vulnerabilities) {
            continue;
        }
        echo "  $name\n";
        foreach ($vulnerabilities as $vulnerability) {
            echo '    - ' . vulnerability_line($vulnerability) . "\n";
        }
    }
}
echo "$phpSupport\n";
echo $updates ? "\nUpdates available (" . count($updates) . ")\n  - " . implode("\n  - ", $updates) . "\n" : "\nUp to date.\n";
if ($warnings) {
    echo "\nWarnings (" . count($warnings) . ")\n  - " . implode("\n  - ", $warnings) . "\n";
}
if ($unknown) {
    echo "\nLatest version unknown (not counted)\n  - " . implode("\n  - ", $unknown) . "\n";
}

$exit = $total > 0 || !$php['supported'] ? EXIT_VULNERABLE : EXIT_OK;
write_report([
    'site'      => $report['site'] ?? $url,
    'env'       => $report['env'] ?? null,
    'status'    => $exit === EXIT_OK ? 'ok' : 'vulnerable',
    'php'       => $php,
    'wordpress' => $wordpress,
    'plugins'   => $plugins,
    'updates'   => $updates,
    'warnings'  => $warnings,
]);
exit($exit);

function fail(string $message): never
{
    fwrite(STDERR, $message . "\n");
    write_report(['error' => $message]);
    exit(EXIT_ERROR);
}

function http_get(string $url, string $headers): array
{
    $context = stream_context_create(['http' => [
        'header'        => $headers,
        'user_agent'    => USER_AGENT,
        'timeout'       => TIMEOUT_SECONDS,
        'ignore_errors' => true,
    ]]);
    $body = @file_get_contents($url, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $match)) {
            $status = (int) $match[1];
        }
    }
    return [$status, $body === false ? '' : $body];
}

function lookup(string $api, string $path): array
{
    [$status, $body] = http_get("$api/$path/", "Accept: application/json\r\n");
    $answer = json_decode($body, true);
    if ($status !== 200 || !is_array($answer) || !empty($answer['error']) || !array_key_exists('data', $answer)) {
        $message = is_array($answer) && !empty($answer['message']) ? " ({$answer['message']})" : '';
        fail("Vulnerability lookup failed: HTTP $status for $api/$path/$message");
    }
    return is_array($answer['data']) ? $answer['data'] : [];
}

function numeric_version(string $version): string
{
    return preg_match('/^\d+(?:\.\d+)*/', $version, $match) ? $match[0] : $version;
}

function plugin_slug(string $file): string
{
    return str_contains($file, '/') ? dirname($file) : basename($file, '.php');
}

function matching(mixed $entries, string $version): array
{
    $found = [];
    foreach (is_array($entries) ? $entries : [] as $entry) {
        if (is_array($entry) && affects($version, $entry['operator'] ?? null)) {
            $found[] = describe($entry, $version);
        }
    }
    return $found;
}

function affects(string $version, mixed $operator): bool
{
    if (!is_array($operator)) {
        return true;
    }
    $min = $operator['min_version'] ?? null;
    $max = $operator['max_version'] ?? null;
    return ($min === null || version_compare($version, (string) $min, $operator['min_operator'] ?? 'ge'))
        && ($max === null || version_compare($version, (string) $max, $operator['max_operator'] ?? 'le'));
}

function describe(array $entry, string $version): array
{
    [$severity, $score] = severity($entry['impact'] ?? null);
    $sources = array_values(array_filter((array) ($entry['source'] ?? []), 'is_array'));
    $ids = array_values(array_filter(array_column($sources, 'id'), 'is_string'));
    $cves = array_filter($ids, fn($id) => str_starts_with($id, 'CVE-'));
    $title = (string) ($entry['name'] ?? '');
    if ($title === '' || $title === $version) {
        $title = (string) ($sources[0]['name'] ?? $sources[0]['description'] ?? $title);
    }
    $operator = $entry['operator'] ?? null;
    $fixed = is_array($operator) && ($operator['max_operator'] ?? null) === 'lt' && empty($operator['unfixed'])
        ? (string) $operator['max_version'] : null;
    return [
        'ids'      => array_values(array_merge($cves, array_diff($ids, $cves))),
        'title'    => $title,
        'severity' => $severity,
        'score'    => $score,
        'fixed_in' => $fixed,
        'links'    => array_values(array_filter(array_column($sources, 'link'), 'is_string')),
    ];
}

function severity(mixed $impact): array
{
    $items = !is_array($impact) ? [] : (array_is_list($impact) ? $impact : [$impact]);
    $best = ['unknown', null];
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }
        $letter = strtolower((string) ($item['cvss']['severity'] ?? ''));
        $name = strtolower((string) ($item['cvss3']['severity'] ?? SEVERITY_LETTERS[$letter] ?? 'unknown'));
        if (!isset(SEVERITY_RANK[$name])) {
            $name = 'unknown';
        }
        if (SEVERITY_RANK[$name] > SEVERITY_RANK[$best[0]]) {
            $best = [$name, $item['cvss3']['score'] ?? $item['cvss']['score'] ?? null];
        }
    }
    return $best;
}

function vulnerability_line(array $vulnerability): string
{
    $details = [];
    if (isset($vulnerability['ids'][0]) && str_starts_with($vulnerability['ids'][0], 'CVE-')) {
        $details[] = $vulnerability['ids'][0];
    }
    if ($vulnerability['fixed_in'] !== null) {
        $details[] = "fixed in {$vulnerability['fixed_in']}";
    }
    return "[{$vulnerability['severity']}] {$vulnerability['title']}" . ($details ? ' (' . implode(', ', $details) . ')' : '');
}

function write_report(array $fields): void
{
    $document = array_replace([
        'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        'site'         => rtrim((string) getenv('WP_AUDIT_URL'), '/') ?: null,
        'env'          => null,
        'status'       => 'error',
        'error'        => null,
        'php'          => null,
        'wordpress'    => null,
        'plugins'      => [],
        'updates'      => [],
        'warnings'     => [],
    ], $fields);
    file_put_contents(JSON_FILE, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}
