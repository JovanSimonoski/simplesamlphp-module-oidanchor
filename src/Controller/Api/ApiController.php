<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateEventRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Utils;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

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
     * Gate every /api/v1/admin/* request. Two accepted credentials:
     *
     *  1. An authenticated SimpleSAMLphp admin session (the Twig admin UI, or an operator
     *     hitting the API directly in a logged-in browser).
     *  2. HTTP Basic against the module-config `api_admin_username` / `api_admin_password`.
     *     This is what the Federation Gateway BFF proxy injects (it strips the caller's Bearer
     *     token and attaches `Authorization: Basic base64(user:pass)` from its instance registry).
     *
     * On failure we emit the spec's `UnauthorizedError` (ErrorResponse) as JSON 401 and stop.
     * We deliberately do NOT fall through to `Utils\Auth::requireAdmin()`, which redirects to the
     * SimpleSAMLphp login page: the gateway proxy follows redirects, so a redirect would make it
     * capture the HTML login page as the API response instead of a clean 401.
     */
    protected function requireAdmin(): void
    {
        // Check HTTP Basic FIRST. It reads only the request header + config and never touches an
        // SSP session — important when this instance is served over plain HTTP behind the gateway
        // proxy: initializing a session there would try to set a secure cookie over HTTP and SSP
        // throws a CriticalConfigurationError ("Setting secure cookie on plain HTTP …") for any
        // Host other than localhost. So the gateway path authenticates without ever starting a
        // session. The session check remains as a fallback for the HTTPS-served Twig admin UI.
        if ($this->basicAuthMatches()) {
            return;
        }

        if ((new Utils\Auth())->isAdmin()) {
            return;
        }

        $this->sendUnauthorized();
    }


    /**
     * Whether the request carries HTTP Basic credentials matching the configured API credential.
     * Returns false (session-only mode) when no credential is configured.
     */
    protected function basicAuthMatches(): bool
    {
        $moduleConfig = $this->moduleConfig();
        $expectedUser = (string) ($moduleConfig->getOptionalString('api_admin_username', '') ?? '');
        $expectedPass = (string) ($moduleConfig->getOptionalString('api_admin_password', '') ?? '');

        if ($expectedUser === '' || $expectedPass === '') {
            return false;
        }

        $credentials = $this->basicCredentials();
        if ($credentials === null) {
            return false;
        }

        [$user, $pass] = $credentials;

        // Constant-time comparison of both fields (evaluate both to avoid short-circuit timing).
        $userOk = hash_equals($expectedUser, $user);
        $passOk = hash_equals($expectedPass, $pass);

        return $userOk && $passOk;
    }


    /**
     * Extract HTTP Basic credentials from the request, coping with the SAPIs that do not populate
     * PHP_AUTH_* (CGI/FastCGI, or an Apache rewrite that hides the header under REDIRECT_*).
     *
     * @return array{0: string, 1: string}|null [username, password], or null when absent/malformed.
     */
    protected function basicCredentials(): ?array
    {
        if (isset($_SERVER['PHP_AUTH_USER'])) {
            return [(string) $_SERVER['PHP_AUTH_USER'], (string) ($_SERVER['PHP_AUTH_PW'] ?? '')];
        }

        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!is_string($header) || stripos($header, 'Basic ') !== 0) {
            return null;
        }

        $decoded = base64_decode(substr($header, 6), true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }

        [$user, $pass] = explode(':', $decoded, 2);

        return [$user, $pass];
    }


    /**
     * Emit the spec's UnauthorizedError as JSON 401 (with a Basic challenge) and end the request.
     * Never returns — the controller method must not continue after auth fails.
     */
    private function sendUnauthorized(): never
    {
        $response = $this->error(
            'unauthorized',
            'Admin authentication required.',
            JsonResponse::HTTP_UNAUTHORIZED,
        );
        $response->headers->set('WWW-Authenticate', 'Basic realm="oidanchor admin API"');
        $response->send();

        exit;
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


    protected function serverError(string $description): JsonResponse
    {
        return $this->error('server_error', $description, JsonResponse::HTTP_INTERNAL_SERVER_ERROR);
    }


    protected function noContent(): Response
    {
        return new Response('', Response::HTTP_NO_CONTENT);
    }


    /**
     * Parse a spec InternalID path value into the integer surrogate id this module assigns.
     * Returns null for values that can never match (non-numeric strings, e.g. UUIDs from
     * other deployments) so callers respond 404.
     */
    protected function internalId(string $value): ?int
    {
        return ctype_digit($value) ? (int) $value : null;
    }


    protected function settings(): SettingsRepository
    {
        return new SettingsRepository($this->buildPdo());
    }


    protected function subordinateService(): SubordinateService
    {
        $pdo = $this->buildPdo();

        return new SubordinateService(
            new SubordinateRepository($pdo),
            new SubordinateEventRepository($pdo),
        );
    }


    /**
     * Resolve the spec's {subordinateID} path parameter (an InternalID) to a subordinate.
     */
    protected function resolveSubordinate(string $subordinateID): ?Subordinate
    {
        $id = $this->internalId($subordinateID);

        return $id !== null ? $this->subordinateService()->findByInternalId($id) : null;
    }


    protected function subordinateNotFound(string $subordinateID): JsonResponse
    {
        return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
    }


    /**
     * Whether a value is a JWKS object carrying at least one key.
     */
    protected function jwksHasKeys(mixed $jwks): bool
    {
        return is_array($jwks)
            && isset($jwks['keys'])
            && is_array($jwks['keys'])
            && $jwks['keys'] !== [];
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
