<?php
/**
 * Plugin Name: WP audit monitor
 * Description: Read-only report of PHP, WordPress core and plugin versions with available updates, read by the wp-audit CI check (https://github.com/cube-agency/wp-audit). Updates themselves happen in git, never on the server.
 * Version: 1.1
 *
 * Endpoint: GET /wp-json/wp-audit/v1/report with the header X-WP-Audit-Token: <token>
 *
 * Switch:
 *   WP_AUDIT_TOKEN  from .env, at least 32 characters (`openssl rand -hex 32`); the same value goes into the
 *                   project's CI variable for the `wp audit` job (image cubesystems/wp-audit).
 *                   Not set or too short: no route is registered and the plugin does nothing.
 *
 * - A wrong or missing token gets the same 404 as a route that doesn't exist.
 * - The token travels in its own header, not Authorization, so HTTP basic auth on staging keeps working.
 * - The report reads the update data WordPress already saved and says when it was checked (checked_at);
 *   only data older than a day triggers one fresh check (sites where cron doesn't run).
 * - Premium plugin versions (their own updaters) are remembered with seen_at, because most updaters run only in
 *   wp-admin — a site needs a wp-admin page view after a licence is added before they show up here.
 * - slug is the wordpress.org slug when WordPress knows it, otherwise the plugin directory (the file name for a
 *   single-file plugin); wp-audit looks vulnerabilities up by it.
 * - latest null means "unknown", never "up to date"; latest_unknown says why:
 *     not_checked  no update check has covered the plugin yet
 *     inactive     not on wordpress.org and inactive, so its own updater never runs
 *     update_uri   its Update URI points away from wordpress.org and its updater hasn't reported yet:
 *                  no wp-admin page view since the licence was added, or no licence
 *     no_source    active, but nothing knows its versions: custom code, a premium plugin not seen in wp-admin
 *                  or without a licence, or a plugin closed on wordpress.org
 * - Responses are sent with no-cache headers. A fastcgi_cache that ignores Cache-Control must skip the path:
 *     if ($request_uri ~* "/wp-json/wp-audit/") { set $skip_cache 1; }
 */

if (!defined('ABSPATH')) {
    exit;
}

const WP_AUDIT_NAMESPACE = 'wp-audit/v1';
const WP_AUDIT_PREMIUM_OPTION = 'wp_audit_premium';

function wp_audit_token(): string
{
    $token = defined('WP_AUDIT_TOKEN') ? (string) WP_AUDIT_TOKEN : (string) ($_ENV['WP_AUDIT_TOKEN'] ?? '');
    return strlen($token) >= 32 ? $token : '';
}

function wp_audit_token_ok(?string $sent): bool
{
    $token = wp_audit_token();
    return $token !== '' && is_string($sent) && $sent !== '' && hash_equals($token, $sent);
}

function wp_audit_is_own_route(): bool
{
    $route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
    return strpos(ltrim((string) $route, '/'), WP_AUDIT_NAMESPACE . '/') === 0;
}

/*
 * 1. Route — only when a token is configured.
 */
add_action('rest_api_init', function () {
    if (wp_audit_token() === '') {
        return;
    }
    register_rest_route(WP_AUDIT_NAMESPACE, '/report', [
        'methods'             => 'GET',
        'callback'            => 'wp_audit_report',
        'permission_callback' => function (WP_REST_Request $request) {
            if (wp_audit_token_ok($request->get_header('x_wp_audit_token'))) {
                return true;
            }
            return new WP_Error('rest_no_route', __('No route was found matching the URL and request method.'), ['status' => 404]);
        },
    ]);
});

/*
 * 2. A valid token passes REST blocks for logged-out visitors on this route only.
 */
add_filter('rest_authentication_errors', function ($result) {
    if (wp_audit_is_own_route() && wp_audit_token_ok($_SERVER['HTTP_X_WP_AUDIT_TOKEN'] ?? null)) {
        return true;
    }
    return $result;
}, 99);

/*
 * 3. Remember premium versions whenever update data is read. Many premium updaters load only in wp-admin and add
 *    their entry on read without saving it (WP Migrate), so the REST request never sees them — any wp-admin page
 *    view fills this cache. Up-to-date entries (no_update) count too. Only the version and when it was seen are
 *    kept — never the package URL, which often carries a licence key. Written at most once a day per plugin.
 */
add_filter('site_transient_update_plugins', function ($value) {
    if (!is_object($value)) {
        return $value;
    }
    $saved = get_option(WP_AUDIT_PREMIUM_OPTION, []);
    $cache = is_array($saved) ? $saved : [];
    foreach (array_merge((array) ($value->no_update ?? []), (array) ($value->response ?? [])) as $file => $item) {
        $item = (object) $item;
        if (wp_audit_is_wporg($item) || empty($item->new_version)) {
            continue;
        }
        if (($cache[$file]['version'] ?? null) !== (string) $item->new_version
            || ($cache[$file]['seen_at'] ?? 0) < time() - DAY_IN_SECONDS) {
            $cache[$file] = ['version' => (string) $item->new_version, 'seen_at' => time()];
        }
    }
    if ($cache !== $saved) {
        update_option(WP_AUDIT_PREMIUM_OPTION, $cache, false);
    }
    return $value;
}, PHP_INT_MAX);

function wp_audit_is_wporg($item): bool
{
    $item = (object) $item;
    return isset($item->id) && strpos((string) $item->id, 'w.org/') === 0;
}

function wp_audit_time(?int $timestamp): ?string
{
    return $timestamp ? gmdate('Y-m-d\TH:i:s\Z', $timestamp) : null;
}

/*
 * 4. Fresh check only when the saved data is missing or older than a day, at most once an hour.
 */
function wp_audit_refresh_if_stale(): void
{
    $stale = false;
    foreach (['update_core', 'update_plugins'] as $transient) {
        $data = get_site_transient($transient);
        if (!is_object($data) || empty($data->last_checked) || $data->last_checked < time() - DAY_IN_SECONDS) {
            $stale = true;
        }
    }
    if (!$stale || get_site_transient('wp_audit_refreshing')) {
        return;
    }
    set_site_transient('wp_audit_refreshing', 1, HOUR_IN_SECONDS);
    wp_version_check();
    wp_update_plugins();
}

function wp_audit_report(): WP_REST_Response
{
    global $wpdb;

    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    wp_audit_refresh_if_stale();

    // Core: the highest version offered; "latest" equals the installed one when nothing newer is out.
    $installed = get_bloginfo('version');
    $update_core = get_site_transient('update_core');
    $core_latest = null;
    foreach ((is_object($update_core) && !empty($update_core->updates)) ? $update_core->updates : [] as $offer) {
        if (!empty($offer->current) && ($core_latest === null || version_compare($offer->current, $core_latest, '>'))) {
            $core_latest = $offer->current;
        }
    }

    // Plugins.
    $update_plugins = get_site_transient('update_plugins');
    $response = is_object($update_plugins) ? (array) ($update_plugins->response ?? []) : [];
    $no_update = is_object($update_plugins) ? (array) ($update_plugins->no_update ?? []) : [];
    $installed_plugins = get_plugins();
    $premium = get_option(WP_AUDIT_PREMIUM_OPTION, []);
    $premium = is_array($premium) ? $premium : [];
    $plugins = [];
    foreach ($installed_plugins as $file => $header) {
        $item = isset($response[$file]) ? (object) $response[$file] : (isset($no_update[$file]) ? (object) $no_update[$file] : null);
        $row = [
            'file'         => $file,
            'slug'         => strpos($file, '/') !== false ? dirname($file) : basename($file, '.php'),
            'name'         => $header['Name'],
            'version'      => $header['Version'],
            'latest'       => null,
            'active'       => is_plugin_active($file),
            'source'       => 'other',
            'requires_php' => $header['RequiresPHP'] ?: null,
        ];
        if ($item && wp_audit_is_wporg($item)) {
            $row['slug'] = $item->slug ?? $row['slug'];
            $row['latest'] = $item->new_version ?? null;
            $row['source'] = 'wporg';
            $row['requires_php'] = $item->requires_php ?? $row['requires_php'];
        } elseif ($item && !empty($item->new_version)) {
            $row['latest'] = $item->new_version;
            $row['source'] = 'premium';
        }
        $cached = $premium[$file] ?? null;
        // A cached version older than the installed one is stale (updated in git since) and ignored.
        if ($row['source'] !== 'wporg' && $cached && version_compare($cached['version'], $header['Version'], '>=')
            && ($row['latest'] === null || version_compare($cached['version'], $row['latest'], '>='))) {
            $row['latest'] = $cached['version'];
            $row['source'] = 'premium';
            $row['seen_at'] = wp_audit_time($cached['seen_at']);
        }
        if ($row['latest'] === null) {
            $update_host = $header['UpdateURI'] ? wp_parse_url($header['UpdateURI'], PHP_URL_HOST) : null;
            if (!is_object($update_plugins) || !isset($update_plugins->checked[$file])) {
                $row['latest_unknown'] = 'not_checked';
            } elseif (!$row['active']) {
                $row['latest_unknown'] = 'inactive';
            } elseif ($header['UpdateURI'] && !in_array($update_host, ['w.org', 'wordpress.org'], true)) {
                $row['latest_unknown'] = 'update_uri';
            } else {
                $row['latest_unknown'] = 'no_source';
            }
        }
        $plugins[] = $row;
    }

    // Cron: how late the most overdue event is (a dead server cron shows up here).
    $cron = _get_cron_array();
    $next = $cron ? min(array_keys($cron)) : null;

    $report = [
        'site'                 => home_url(),
        'env'                  => wp_get_environment_type(),
        'generated_at'         => wp_audit_time(time()),
        'core'                 => [
            'version'    => $installed,
            'latest'     => $core_latest,
            'checked_at' => wp_audit_time(is_object($update_core) ? (int) ($update_core->last_checked ?? 0) : null),
        ],
        'php'                  => PHP_VERSION,
        'db'                   => method_exists($wpdb, 'db_server_info') ? $wpdb->db_server_info() : $wpdb->db_version(),
        'multisite'            => is_multisite(),
        'plugins_checked_at'   => wp_audit_time(is_object($update_plugins) ? (int) ($update_plugins->last_checked ?? 0) : null),
        'plugins'              => $plugins,
        'mu_plugins'           => array_keys(get_mu_plugins()),
        'flags'                => [
            'DISALLOW_FILE_MODS' => defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS,
            'WP_DEBUG'           => defined('WP_DEBUG') && WP_DEBUG,
            'WP_DEBUG_DISPLAY'   => defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY,
            'DISABLE_WP_CRON'    => defined('DISABLE_WP_CRON') && DISABLE_WP_CRON,
            'cron_overdue_min'   => $next ? max(0, (int) floor((time() - $next) / 60)) : 0,
            'blog_public'        => (bool) get_option('blog_public'),
        ],
    ];

    $result = new WP_REST_Response($report);
    $result->set_headers(wp_get_nocache_headers() + ['X-Robots-Tag' => 'noindex, nofollow']);
    return $result;
}
