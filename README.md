# wp-audit

Vulnerability check for a WordPress site, shipped as the Docker image `cubesystems/wp-audit`
together with the mu-plugin it reads. The tool fetches the site's PHP, WordPress core and plugin
versions from its `cube-monitor` endpoint, looks them up in
[WPVulnerability](https://www.wpvulnerability.net) and lists what applies. Nothing is changed on the site.

## Site plugin

Copy `mu-plugin/cube-monitor.php` into `wp-content/mu-plugins/` and set `WP_AUDIT_TOKEN` in the
server's `.env` (`openssl rand -hex 32`). The report is served at `GET /wp-json/cube-monitor/v1/report`
to requests with the header `X-Cube-Monitor-Token`. This file is the source of truth; site copies are
updated by copying it again.

## CI job

```yaml
wp audit:
  stage: check
  image: cubesystems/wp-audit:1.0@sha256:<digest>
  needs: []
  dependencies: []
  variables:
    GIT_STRATEGY: none
    WP_AUDIT_URL: https://www.example.com
  environment:
    name: production
    action: verify
  script:
    - wp-audit
  artifacts:
    when: always
    expire_in: 30 days
    paths:
      - wp-audit.json
```

`WP_AUDIT_TOKEN` is the plugin's token, passed as a masked CI variable. `wp-audit.json` is read by Seer
for the PHP and WordPress versions. `WP_AUDIT_API` overrides the vulnerability API, default
`https://www.wpvulnerability.net`.

## Output

The log lists vulnerabilities per component with severity, CVE and fixed version, the PHP branch's
support status, pending updates, warnings (update data older than two days; on production
`DISALLOW_FILE_MODS` off, `WP_DEBUG_DISPLAY` on, search engines discouraged, WP-Cron over an hour
overdue) and plugins whose latest version is unknown. Plugins outside wordpress.org are looked up by
directory name. Themes are not checked.

Exit `2`: a vulnerability applies or the PHP branch is out of support. Exit `1`: the check could not
run. Updates and warnings never fail the job.

`wp-audit.json` is written in every case; `status` is `ok`, `vulnerable` or `error`:

```json
{
  "generated_at": "2026-10-29T18:00:00Z", "site": "https://www.example.com", "env": "production",
  "status": "vulnerable", "error": null,
  "php": { "version": "8.3.6", "supported": true, "support_until": "2027-12-31", "vulnerabilities": [] },
  "wordpress": { "version": "6.8.2", "latest": "7.1.4", "vulnerabilities": [] },
  "plugins": [{ "file": "akismet/akismet.php", "slug": "akismet", "name": "Akismet", "version": "5.3", "latest": "5.4", "active": true,
                "vulnerabilities": [{ "ids": ["CVE-2024-0001"], "title": "Akismet < 5.3.1 - XSS", "severity": "high", "score": "7.5", "fixed_in": "5.3.1", "links": ["https://www.cve.org/CVERecord?id=CVE-2024-0001"] }] }],
  "updates": ["WordPress 6.8.2 → 7.1.4", "Akismet 5.3 → 5.4"],
  "warnings": []
}
```

## Development

```sh
php -l wp-audit.php mu-plugin/cube-monitor.php
bash test/smoke.sh
```
