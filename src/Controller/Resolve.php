<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Exception\ResolveException;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\RateLimitRepository;
use SimpleSAML\Module\oidanchor\Repository\ResolveCacheRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\FederationResolver;
use SimpleSAML\Module\oidanchor\Service\TrustMarkStatusService;
use SimpleSAML\Module\oidanchor\Validation\Url;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Public Resolve endpoint.
 *
 * GET /resolve?sub=<entity>&trust_anchor=<TA>[&type=<entity_type>]
 *
 * Returns a signed Resolve Response (typ: resolve-response+jwt) with the policy-applied metadata,
 * the verified trust chain and the validated Trust Marks. No admin authentication.
 *
 * Each resolution fetches remote statements, so the endpoint is hardened against abuse:
 * responses are cached briefly (resolve.cache_ttl), cache misses are rate-limited per client
 * (resolve.rate_limit), outbound fetches only reach public addresses (see FederationHttpClient),
 * and fetch failures are reported without network detail.
 */
class Resolve
{
    use JwtResponseTrait;


    /** Seconds a signed Resolve Response is reused for the same request. */
    private const int DEFAULT_CACHE_TTL = 300;

    /** Resolutions (cache misses) per client IP per minute. */
    private const int DEFAULT_RATE_LIMIT = 30;


    public function __construct(
        protected Configuration $config,
    ) {
    }


    public function resolve(Request $request): Response
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        $sub         = trim((string) $request->query->get('sub', ''));
        $trustAnchor = trim((string) $request->query->get('trust_anchor', ''));
        $type        = trim((string) $request->query->get('type', '')) ?: null;

        if ($sub === '' || $trustAnchor === '') {
            return $this->error(
                'invalid_request',
                'Both sub and trust_anchor query parameters are required.',
                Response::HTTP_BAD_REQUEST,
            );
        }

        if (!Url::isHttps($sub) || !Url::isHttps($trustAnchor)) {
            return $this->error(
                'invalid_request',
                'sub and trust_anchor must be HTTPS URLs.',
                Response::HTTP_BAD_REQUEST,
            );
        }

        $settings  = $moduleConfig->getOptionalArray('resolve', []);
        $cacheTtl  = (int) ($settings['cache_ttl'] ?? self::DEFAULT_CACHE_TTL);
        $rateLimit = (int) ($settings['rate_limit'] ?? self::DEFAULT_RATE_LIMIT);

        try {
            $pdo      = PdoFactory::get($moduleConfig);
            $cache    = new ResolveCacheRepository($pdo);
            $cacheKey = ResolveCacheRepository::keyFor($sub, $trustAnchor, $type);

            if ($cacheTtl > 0 && ($cached = $cache->get($cacheKey)) !== null) {
                return $this->jwtResponse($cached, 'application/' . FederationKeyService::RESOLVE_RESPONSE_TYP);
            }

            // Only cache misses do outbound work, so only they count against the client's limit.
            if ($rateLimit > 0) {
                $client     = 'resolve:' . hash('sha256', (string) $request->getClientIp());
                $retryAfter = (new RateLimitRepository($pdo))->hit($client, $rateLimit, 60);
                if ($retryAfter !== null) {
                    $response = $this->error(
                        'temporarily_unavailable',
                        'Too many resolve requests; try again later.',
                        Response::HTTP_TOO_MANY_REQUESTS,
                    );
                    $response->headers->set('Retry-After', (string) $retryAfter);

                    return $response;
                }
            }

            $keys     = new FederationKeyService($moduleConfig, $pdo);
            $resolver = new FederationResolver(
                $moduleConfig,
                $keys,
                new TrustMarkStatusService(
                    $keys,
                    new IssuedTrustMarkRepository($pdo),
                    new TrustMarkSubjectRepository($pdo),
                ),
            );

            $result = $resolver->resolve($sub, $trustAnchor, $type);
            $token  = $resolver->buildSignedResponse($result);

            Logger::info(sprintf(
                'oidanchor: resolve sub=%s trust_anchor=%s -> ok (%d chain statements, %d trust marks, %d warnings)',
                $sub,
                $trustAnchor,
                count($result->trustChainTokens),
                count($result->trustMarks),
                count($result->warnings),
            ));

            if ($cacheTtl > 0) {
                $cache->put($cacheKey, $token, min(time() + $cacheTtl, $this->jwtExpiration($token) ?? PHP_INT_MAX));
            }

            return $this->jwtResponse(
                $token,
                'application/' . FederationKeyService::RESOLVE_RESPONSE_TYP,
            );
        } catch (ResolveException $e) {
            Logger::info(sprintf('oidanchor: resolve sub=%s -> %s (%s)', $sub, $e->errorCode, $e->getMessage()));

            return $this->error($e->errorCode, self::publicDescription($e), $e->httpStatus);
        } catch (Throwable $e) {
            Logger::error('oidanchor: resolve failed: ' . $e->getMessage());

            return $this->error('server_error', 'Unable to resolve the requested entity.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    /**
     * The error description for the caller. Fetch and chain failures carry the underlying network
     * error (connection refused, timeout, the address that was tried), which would tell an anonymous
     * caller whether a host is reachable from this server; they get a generic description, and the
     * detail goes to the log (and to the admin resolve tester).
     */
    private static function publicDescription(ResolveException $e): string
    {
        return match ($e->errorCode) {
            'not_found'           => 'The Entity Configuration of the subject could not be fetched.',
            'invalid_trust_chain' => 'No valid trust chain from the subject to the trust anchor could be established.',
            default               => $e->getMessage(),
        };
    }


    private function error(string $error, string $description, int $status): JsonResponse
    {
        return new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            $status,
        );
    }
}
