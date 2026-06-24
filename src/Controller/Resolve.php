<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Exception\ResolveException;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\FederationResolver;
use SimpleSAML\Module\oidanchor\Service\TrustMarkStatusService;
use Throwable;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Public Resolve endpoint.
 *
 * GET /resolve?sub=<entity>&trust_anchor=<TA>[&type=<entity_type>]
 *
 * Returns a signed Resolve Response (typ: resolve-response+jwt) with the policy-applied metadata,
 * the verified trust chain and the validated Trust Marks. No admin authentication.
 */
class Resolve
{
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

        if (!$this->isHttpsUrl($sub) || !$this->isHttpsUrl($trustAnchor)) {
            return $this->error(
                'invalid_request',
                'sub and trust_anchor must be HTTPS URLs.',
                Response::HTTP_BAD_REQUEST,
            );
        }

        try {
            $keys     = new FederationKeyService($moduleConfig);
            $resolver = new FederationResolver(
                $moduleConfig,
                $keys,
                new TrustMarkStatusService($keys, new IssuedTrustMarkRepository($this->buildPdo($moduleConfig))),
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

            return new Response(
                $token,
                Response::HTTP_OK,
                ['Content-Type' => 'application/' . FederationKeyService::RESOLVE_RESPONSE_TYP],
            );
        } catch (ResolveException $e) {
            Logger::info(sprintf('oidanchor: resolve sub=%s -> %s (%s)', $sub, $e->errorCode, $e->getMessage()));

            return $this->error($e->errorCode, $e->getMessage(), $e->httpStatus);
        } catch (Throwable $e) {
            Logger::error('oidanchor: resolve failed: ' . $e->getMessage());

            return $this->error('server_error', 'Unable to resolve the requested entity.', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }


    private function buildPdo(Configuration $moduleConfig): PDO
    {
        try {
            return new PDO(
                $moduleConfig->getString('database_dsn'),
                $moduleConfig->getOptionalString('database_username', null),
                $moduleConfig->getOptionalString('database_password', null),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ],
            );
        } catch (PDOException $e) {
            throw new RuntimeException('oidanchor: cannot connect to database: ' . $e->getMessage(), 0, $e);
        }
    }


    private function error(string $error, string $description, int $status): JsonResponse
    {
        return new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            $status,
        );
    }
}
