#!/usr/bin/env bash
set -euo pipefail

PACKAGE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wp-audit-test.XXXXXX")
SERVER_PID=
trap 'rm -rf "$TEST_DIR"; [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true' EXIT
mkdir -p "$TEST_DIR/work"

PORT=$(php -r '$server = stream_socket_server("tcp://127.0.0.1:0"); echo explode(":", stream_socket_get_name($server, false))[1];')
php -S "127.0.0.1:$PORT" "$PACKAGE_DIR/test/fixtures/router.php" > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
php -r 'for ($i = 0; $i < 50; $i++) { if (@fsockopen("127.0.0.1", (int) $argv[1])) { exit(0); } usleep(100000); } exit(1);' "$PORT"

export WP_AUDIT_API="http://127.0.0.1:$PORT/api"
export WP_AUDIT_TOKEN=test-token-0123456789abcdef0123456789abcdef
SITE="http://127.0.0.1:$PORT/site"

check_run() {
    local name=$1 expected=$2 status=0
    shift 2
    rm -f "$TEST_DIR/work"/wp-audit.*
    (cd "$TEST_DIR/work" && env "$@" php "$PACKAGE_DIR/wp-audit.php") > "$TEST_DIR/$name.log" 2>&1 || status=$?
    if [[ "$status" != "$expected" ]]; then cat "$TEST_DIR/$name.log"; echo "FAIL $name: exit $status, expected $expected" >&2; exit 1; fi
    [[ -s "$TEST_DIR/work/wp-audit.json" ]]
    php -r 'json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);' "$TEST_DIR/work/wp-audit.json"
    echo "PASS $name"
}
json() {
    php -r '$value = json_decode(file_get_contents($argv[1]), true); foreach (explode(".", $argv[2]) as $key) { $value = $value[$key] ?? null; } echo is_scalar($value) && !is_bool($value) ? $value : json_encode($value);' "$TEST_DIR/work/wp-audit.json" "$1"
}
expect() {
    local actual
    actual=$(json "$1")
    if [[ "$actual" != "$2" ]]; then echo "FAIL $1: '$actual', expected '$2'" >&2; exit 1; fi
}

check_run vulnerable 2 WP_AUDIT_URL="$SITE/vulnerable"
log="$TEST_DIR/vulnerable.log"
grep -qx 'https://www.example.test (production) · WordPress 6.7 · PHP 8.1.2-1ubuntu2.14 · checked 2026-01-01T06:00:00Z' "$log"
grep -qx 'Vulnerabilities (6)' "$log"
grep -qx '    - \[critical\] PHP 8.1 < 8.1.22 (CVE-2023-3824, fixed in 8.1.22)' "$log"
grep -qx '    - \[medium\] PHP 8.1 < 8.1.3 (CVE-2021-0002, fixed in 8.1.3)' "$log"
! grep -q 'CVE-2022-0001' "$log"
grep -qx 'PHP 8.1 support ended 2025-12-31' "$log"
grep -qx '    - \[unknown\] WordPress <= 6.9.1 - Authenticated (Author+) XML External Entity Injection' "$log"
grep -qx '    - \[medium\] WordPress < 6.7.1 - Stored XSS (CVE-2025-0003)' "$log"
grep -qx '    - \[high\] Akismet Anti-spam: Spam Protection \[akismet\] < 5.3.1 (CVE-2024-0001, fixed in 5.3.1)' "$log"
grep -qx '    - \[critical\] Advanced Custom Field Pro \[advanced-custom-fields-pro\] < 6.3.1 (CVE-2025-0004, fixed in 6.3.1)' "$log"
! grep -q 'Yoast' "$log"
grep -qx 'Updates available (3)' "$log"
grep -qx '  - WordPress 6.7 → 7.1.4' "$log"
grep -qx '  - Akismet 5.3 → 5.4' "$log"
grep -qx '  - Advanced Custom Fields PRO 6.3.0 → 6.4.0 (seen 2026-10-01)' "$log"
grep -qx 'Warnings (2)' "$log"
grep -q '^  - Update data is [0-9]* days old - can the server reach api.wordpress.org?$' "$log"
grep -qx '  - DISALLOW_FILE_MODS is off - plugins can be changed outside git' "$log"
grep -qx '  - Custom Thing 1.0: no_source' "$log"
grep -qx '  - Hello Dolly (inactive) 1.7.2: inactive' "$log"
expect status vulnerable
expect error null
expect php.version 8.1.2
expect php.supported false
expect php.support_until 2025-12-31
expect wordpress.version 6.7
expect wordpress.latest 7.1.4
expect plugins.0.slug akismet
expect plugins.0.vulnerabilities.0.ids '["CVE-2024-0001","1a2f3094-5970-4251-9ed0-ec595a0cd26c"]'
expect plugins.0.vulnerabilities.0.score 7.5
expect plugins.2.slug advanced-custom-fields-pro
expect plugins.3.latest_unknown no_source
expect plugins.4.slug hello
expect plugins.4.active false
expect updates.0 'WordPress 6.7 → 7.1.4'

check_run clean 0 WP_AUDIT_URL="$SITE/clean"
log="$TEST_DIR/clean.log"
grep -qx 'No known vulnerabilities.' "$log"
grep -qx 'PHP 8.3 supported until 2027-12-31' "$log"
grep -qx 'Up to date.' "$log"
! grep -q 'Warnings' "$log"
expect status ok
expect php.version 8.3.6
expect php.supported true
expect wordpress.version 7.1.4
expect plugins.0.vulnerabilities '[]'

check_run missing-site 1 WP_AUDIT_URL="$SITE/missing"
grep -qx "Report failed: HTTP 404 (cube-monitor missing or token not set on the server) from $SITE/missing" "$TEST_DIR/missing-site.log"
expect status error
expect php null
expect wordpress null
expect plugins '[]'

check_run wrong-token 1 WP_AUDIT_URL="$SITE/clean" WP_AUDIT_TOKEN=wrong
grep -q '^Report failed: HTTP 404' "$TEST_DIR/wrong-token.log"

check_run unreachable-site 1 WP_AUDIT_URL="http://127.0.0.1:1/site/clean"
grep -q '^Report failed: HTTP 0 (site unreachable)' "$TEST_DIR/unreachable-site.log"

check_run api-down 1 WP_AUDIT_URL="$SITE/clean" WP_AUDIT_API="http://127.0.0.1:$PORT/down"
grep -q "^Vulnerability lookup failed: HTTP 500 for http://127.0.0.1:$PORT/down/php/8.3.6/ (maintenance)" "$TEST_DIR/api-down.log"
expect status error

check_run missing-env 1 -u WP_AUDIT_URL -u WP_AUDIT_TOKEN
grep -qx 'WP_AUDIT_URL and WP_AUDIT_TOKEN not set - CI/CD variable missing, protected on an unprotected branch, or scoped to another environment' "$TEST_DIR/missing-env.log"
expect status error
expect error 'WP_AUDIT_URL and WP_AUDIT_TOKEN not set - CI/CD variable missing, protected on an unprotected branch, or scoped to another environment'

echo 'All smoke tests passed'
