<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use GuzzleHttp\Client;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;

/**
 * The HTTP client for every outbound federation fetch (resolve chain walks, external trust
 * mark refreshes): bounded connect/read timeouts, TLS verification, and a single https-only
 * redirect. Settings come from the `resolve` block of the module config.
 *
 * Without this, simplesamlphp/openid falls back to Guzzle's defaults (no timeouts at all).
 */
final class FederationHttpClient
{
    public static function create(Configuration $moduleConfig, string $userAgent): Client
    {
        $r = $moduleConfig->getOptionalArray('resolve', []);

        $verifyTls = array_key_exists('http_verify_tls', $r) ? (bool) $r['http_verify_tls'] : true;
        if (!$verifyTls) {
            Logger::warning('oidanchor: TLS verification is DISABLED for outbound federation fetches (resolve.http_verify_tls). Development use only.');
        }

        return new Client([
            'connect_timeout' => (int) ($r['http_connect_timeout'] ?? 5),
            'timeout'         => (int) ($r['http_read_timeout'] ?? 5),
            'allow_redirects' => ['max' => 1, 'strict' => true, 'referer' => false, 'protocols' => ['https']],
            'verify'          => $verifyTls,
            'http_errors'     => true,
            'headers'         => ['User-Agent' => $userAgent],
        ]);
    }
}
