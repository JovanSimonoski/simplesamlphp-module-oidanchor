<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkStatusService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use Throwable;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Public Trust Mark Status endpoint.
 *
 * GET /trust_mark_status?trust_mark_type=<type>&sub=<entity>
 *   or
 * GET /trust_mark_status?trust_mark=<compact JWT>
 *
 * Returns a signed Trust Mark Status Response (typ: trust-mark-status-response+jwt) describing
 * whether the mark is active, expired, revoked or invalid. No admin authentication — this is
 * how third parties verify marks the TA has issued.
 */
class TrustMarkStatus
{
    public function __construct(
        protected Configuration $config,
    ) {
    }


    public function status(Request $request): Response
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        // Accept the library's claim name plus historical aliases for the type identifier.
        $trustMarkType = $this->firstNonEmpty(
            $request->query->get('trust_mark_type'),
            $request->query->get('trust_mark_id'),
            $request->query->get('id'),
        );
        $sub       = $this->firstNonEmpty($request->query->get('sub'));
        $trustMark = $this->firstNonEmpty($request->query->get('trust_mark'));

        // Require either the full mark, or the (type + sub) pair.
        if ($trustMark === null && ($trustMarkType === null || $sub === null)) {
            return $this->error(
                'invalid_request',
                'Provide either trust_mark, or both trust_mark_type and sub.',
                Response::HTTP_BAD_REQUEST,
            );
        }

        try {
            $keys = new FederationKeyService($moduleConfig);

            $service = new TrustMarkStatusService(
                $keys,
                new IssuedTrustMarkRepository($this->buildPdo($moduleConfig)),
            );

            $result = $service->getStatus($trustMarkType, $sub, $trustMark);

            $now      = time();
            $lifetime = $moduleConfig->getOptionalInteger('trust_mark_status_response_lifetime', 600) ?? 600;

            $payload = [
                ClaimsEnum::Iss->value    => $keys->entityId(),
                ClaimsEnum::Iat->value    => $now,
                ClaimsEnum::Exp->value    => $now + $lifetime,
                ClaimsEnum::Status->value => $result['status'],
            ];

            if ($result['sub'] !== null) {
                $payload[ClaimsEnum::Sub->value] = $result['sub'];
            }
            if ($result['trust_mark_type'] !== null) {
                $payload[ClaimsEnum::TrustMarkType->value] = $result['trust_mark_type'];
            }
            if ($result['trust_mark'] !== null) {
                $payload[ClaimsEnum::TrustMark->value] = $result['trust_mark'];
            }

            $token = $keys->signTrustMarkStatusResponse($payload);

            Logger::info(sprintf(
                'oidanchor: trust_mark_status query type=%s sub=%s -> %s',
                $result['trust_mark_type'] ?? '(none)',
                $result['sub'] ?? '(none)',
                $result['status'],
            ));

            return new Response(
                $token,
                Response::HTTP_OK,
                ['Content-Type' => 'application/' . JwtTypesEnum::TrustMarkStatusResponseJwt->value],
            );
        } catch (Throwable $e) {
            Logger::error('oidanchor: trust_mark_status failed: ' . $e->getMessage());

            return $this->error(
                'server_error',
                'Unable to produce a Trust Mark status response.',
                Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }
    }


    private function firstNonEmpty(?string ...$values): ?string
    {
        foreach ($values as $value) {
            if ($value !== null && trim($value) !== '') {
                return trim($value);
            }
        }

        return null;
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
