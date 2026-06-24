<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Utils;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Base class for the Federation Admin REST API controllers (/api/v1/admin/...).
 *
 * Provides shared concerns: admin authentication (reusing the SimpleSAMLphp admin session),
 * a consistent JSON error envelope matching the OpenAPI `ErrorResponse` schema, JSON body
 * decoding, and a PDO connection to the module database.
 */
abstract class ApiController
{
    public function __construct(
        protected Configuration $config,
    ) {
    }


    /**
     * Require an authenticated SimpleSAMLphp admin session (decision: reuse admin auth).
     */
    protected function requireAdmin(): void
    {
        (new Utils\Auth())->requireAdmin();
    }


    protected function moduleConfig(): Configuration
    {
        return Configuration::getConfig('module_oidanchor.php');
    }


    /**
     * JSON success response with unescaped slashes (entity IDs are URLs).
     */
    protected function json(mixed $data, int $status = JsonResponse::HTTP_OK): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->setEncodingOptions(JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $response;
    }


    /**
     * Error envelope matching the spec's ErrorResponse { error, error_description }.
     */
    protected function error(string $error, string $description, int $status): JsonResponse
    {
        return new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            $status,
        );
    }


    protected function notFound(string $description = 'Resource not found.'): JsonResponse
    {
        return $this->error('not_found', $description, JsonResponse::HTTP_NOT_FOUND);
    }


    protected function badRequest(string $description): JsonResponse
    {
        return $this->error('invalid_request', $description, JsonResponse::HTTP_BAD_REQUEST);
    }


    protected function conflict(string $description): JsonResponse
    {
        return $this->error('invalid_request', $description, JsonResponse::HTTP_CONFLICT);
    }


    /**
     * Decode a JSON request body. Returns the decoded value, or null on empty/invalid body.
     */
    protected function decodeJson(Request $request): mixed
    {
        $raw = trim($request->getContent());
        if ($raw === '') {
            return null;
        }

        return json_decode($raw, true);
    }


    /**
     * Raw request body as a trimmed string (for text/plain bodies, e.g. status / lifetime).
     */
    protected function bodyString(Request $request): string
    {
        return trim($request->getContent());
    }


    protected function buildPdo(): PDO
    {
        $moduleConfig = $this->moduleConfig();

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
}
