<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\admin\Controller\Menu;
use SimpleSAML\Module\oidanchor\Exception\ResolveException;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\FederationResolver;
use SimpleSAML\Module\oidanchor\Service\TrustMarkStatusService;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Admin "Resolve Tester": run a resolution from the admin UI without crafting URLs.
 *
 * Calls {@see FederationResolver} in-process (no HTTP self-call) and renders the resolved
 * metadata, the decoded trust chain, the validated Trust Marks, any warnings, and the signed
 * Resolve Response JWT. Requires admin auth; the form carries a CSRF token.
 */
class AdminResolve
{
    public function __construct(
        protected Configuration $config,
    ) {
    }


    public function index(Request $request): Template
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        $entityId     = $moduleConfig->getString('entity_id');

        $formData = [
            'sub'          => '',
            'trust_anchor' => $entityId,
            'type'         => '',
        ];

        $error = null;
        $view  = null;

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                $error = ['code' => 'invalid_request', 'description' => 'Invalid or missing CSRF token. Please try again.'];
            } else {
                $formData = [
                    'sub'          => trim((string) $request->request->get('sub', '')),
                    'trust_anchor' => trim((string) $request->request->get('trust_anchor', '')),
                    'type'         => trim((string) $request->request->get('type', '')),
                ];

                try {
                    $pdo      = $this->buildPdo($moduleConfig);
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

                    $result = $resolver->resolve(
                        $formData['sub'],
                        $formData['trust_anchor'],
                        $formData['type'] !== '' ? $formData['type'] : null,
                    );

                    $view = [
                        'metadata'   => $this->pretty($result->metadata),
                        'chain'      => $this->chainView($result->trustChain->getEntities()),
                        'trustMarks' => $this->marksView($result->trustMarks),
                        'warnings'   => $result->warnings,
                        'token'      => $resolver->buildSignedResponse($result),
                    ];

                    Logger::info(sprintf(
                        'oidanchor: admin resolve tester sub=%s -> ok (admin: %s)',
                        $formData['sub'],
                        $this->getAdminUsername(),
                    ));
                } catch (ResolveException $e) {
                    $error = ['code' => $e->errorCode, 'description' => $e->getMessage()];
                    Logger::info(sprintf(
                        'oidanchor: admin resolve tester sub=%s -> %s (admin: %s)',
                        $formData['sub'],
                        $e->errorCode,
                        $this->getAdminUsername(),
                    ));
                } catch (Throwable $e) {
                    $error = ['code' => 'server_error', 'description' => $e->getMessage()];
                    Logger::error('oidanchor: admin resolve tester failed: ' . $e->getMessage());
                }
            }
        }

        $t = new Template($this->config, 'oidanchor:admin_resolve.twig');
        $t->data['formData']  = $formData;
        $t->data['error']     = $error;
        $t->data['view']      = $view;
        $t->data['actionUrl'] = Module::getModuleURL('oidanchor/admin/resolve');
        $t->data['csrfToken'] = $this->csrfToken();
        $t->data['logouturl'] = $authUtils->getAdminLogoutURL();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @param \SimpleSAML\OpenID\Federation\EntityStatement[] $entities
     * @return list<array{iss:string,sub:string,header:string,payload:string}>
     */
    private function chainView(array $entities): array
    {
        $view = [];
        foreach ($entities as $statement) {
            try {
                $view[] = [
                    'iss'     => (string) ($statement->getIssuer() ?? ''),
                    'sub'     => (string) ($statement->getSubject() ?? ''),
                    'header'  => $this->pretty($statement->getHeader()),
                    'payload' => $this->pretty($statement->getPayload()),
                ];
            } catch (Throwable) {
                // Skip a statement we cannot introspect.
            }
        }

        return $view;
    }


    /**
     * @param list<array{trust_mark_type:string,trust_mark:string}> $trustMarks
     * @return list<array{type:string,payload:string}>
     */
    private function marksView(array $trustMarks): array
    {
        return array_map(
            fn(array $m): array => [
                'type'    => $m['trust_mark_type'],
                'payload' => $this->lenientPayload($m['trust_mark']),
            ],
            $trustMarks,
        );
    }


    /**
     * @param array<string,mixed> $data
     */
    private function pretty(array $data): string
    {
        return (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }


    private function lenientPayload(string $jwt): string
    {
        $parts = explode('.', $jwt);
        if (!isset($parts[1])) {
            return '';
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }

        $json = json_decode($decoded, true);

        return is_array($json) ? $this->pretty($json) : $decoded;
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


    private function csrfToken(): string
    {
        $session = Session::getSessionFromRequest();
        $token   = $session->getData('oidanchor_csrf', 'token');

        if (!is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(32));
            $session->setData('oidanchor_csrf', 'token', $token);
        }

        return $token;
    }


    private function assertCsrf(Request $request): bool
    {
        $session  = Session::getSessionFromRequest();
        $expected = $session->getData('oidanchor_csrf', 'token');
        $provided = (string) $request->request->get('csrf_token', '');

        return is_string($expected) && $expected !== '' && hash_equals($expected, $provided);
    }


    private function getAdminUsername(): string
    {
        try {
            $session = Session::getSessionFromRequest();
            $authId  = $session->getAuthData('admin', 'Attributes');

            if (is_array($authId) && isset($authId['uid'][0])) {
                return (string) $authId['uid'][0];
            }
        } catch (Throwable) {
            // Best-effort.
        }

        return 'admin';
    }
}
