<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\RequestInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;

/**
 * The HTTP client for every outbound federation fetch (resolve chain walks, external trust
 * mark refreshes): bounded connect/read timeouts, TLS verification, and a single https-only
 * redirect. Settings come from the `resolve` block of the module config.
 *
 * Unless `resolve.allow_private_networks` is set, requests may only reach globally routable
 * addresses: the target host is resolved, every address must be public, and the connection is
 * pinned to the checked address (so a DNS answer cannot change between the check and the
 * connect). This stops /resolve — which fetches URLs chosen by the caller and by the entities
 * it walks through — from being used to reach internal services.
 *
 * Without this class, simplesamlphp/openid falls back to Guzzle's defaults (no timeouts at all).
 */
final class FederationHttpClient
{
    /**
     * @param callable|null $handler The underlying HTTP handler (tests); Guzzle's default otherwise.
     */
    public static function create(Configuration $moduleConfig, string $userAgent, ?callable $handler = null): Client
    {
        $r = $moduleConfig->getOptionalArray('resolve', []);

        $verifyTls = array_key_exists('http_verify_tls', $r) ? (bool) $r['http_verify_tls'] : true;
        if (!$verifyTls) {
            Logger::warning('oidanchor: TLS verification is DISABLED for outbound federation fetches (resolve.http_verify_tls). Development use only.');
        }

        $stack = HandlerStack::create($handler);
        if (!(bool) ($r['allow_private_networks'] ?? false)) {
            // Pushed last, so it runs closest to the handler: redirect targets are checked too.
            $stack->push(self::publicHostsOnly(), 'oidanchor_public_hosts_only');
        }

        return new Client([
            'handler'         => $stack,
            'connect_timeout' => (int) ($r['http_connect_timeout'] ?? 5),
            'timeout'         => (int) ($r['http_read_timeout'] ?? 5),
            'allow_redirects' => ['max' => 1, 'strict' => true, 'referer' => false, 'protocols' => ['https']],
            'verify'          => $verifyTls,
            'http_errors'     => true,
            'headers'         => ['User-Agent' => $userAgent],
        ]);
    }


    /**
     * The globally routable address to connect to for $host.
     *
     * @throws \RuntimeException When the host does not resolve, or resolves to any address that is
     *     not globally routable (loopback, private, link-local, reserved, ...).
     */
    public static function publicAddress(string $host): string
    {
        $host = trim($host, '[]');

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $addresses = [$host];
        } else {
            $addresses = gethostbynamel($host) ?: [];
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                    $addresses[] = $record['ipv6'];
                }
            }
        }

        if ($addresses === []) {
            throw new \RuntimeException(sprintf('Host "%s" does not resolve.', $host));
        }

        // Every address must be public: the connection could otherwise be steered to any of them.
        foreach ($addresses as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false) {
                throw new \RuntimeException(sprintf('Host "%s" resolves to a non-public address.', $host));
            }
        }

        return $addresses[0];
    }


    private static function publicHostsOnly(): callable
    {
        return static fn(callable $next): callable => static function (RequestInterface $request, array $options) use ($next) {
            $uri  = $request->getUri();
            $host = $uri->getHost();

            try {
                $address = self::publicAddress($host);
            } catch (\RuntimeException $e) {
                throw new ConnectException('oidanchor: refused outbound fetch: ' . $e->getMessage(), $request, $e);
            }

            // Pin curl to the address that was checked. Without ext-curl Guzzle uses its stream
            // handler, which cannot be pinned; the address check above still applies.
            if (defined('CURLOPT_RESOLVE')) {
                $port = $uri->getPort() ?? ($uri->getScheme() === 'http' ? 80 : 443);
                $options['curl'][CURLOPT_RESOLVE] = [sprintf(
                    '%s:%d:%s',
                    trim($host, '[]'),
                    $port,
                    str_contains($address, ':') ? '[' . $address . ']' : $address,
                )];
            }

            return $next($request, $options);
        };
    }
}
