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
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkIssuer;
use SimpleSAML\Module\oidanchor\Validation\IssuedTrustMarkValidator;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Admin UI controller for issued Trust Marks: listing, issuance, viewing and revocation.
 *
 * All methods require admin authentication; state-changing methods require a valid CSRF token.
 */
class AdminTrustMarks
{
    private const FLASH_KEY = 'oidanchor_tm_flash';


    public function __construct(
        protected Configuration $config,
    ) {
    }


    public function list(Request $request): Template
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $filterType   = trim((string) $request->query->get('trust_mark_id', '')) ?: null;
        $filterSub    = trim((string) $request->query->get('sub', '')) ?: null;
        $filterStatus = trim((string) $request->query->get('status', '')) ?: null;

        $issuedRepo = $this->issuedRepository();
        $typeRepo   = $this->typeRepository();

        $marks = $issuedRepo->findAll($filterType, $filterSub, $filterStatus);

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_list.twig');
        $t->data['marks']        = $marks;
        $t->data['types']        = $typeRepo->findAll();
        $t->data['filter']       = ['trust_mark_id' => $filterType, 'sub' => $filterSub, 'status' => $filterStatus];
        $t->data['issueUrl']     = Module::getModuleURL('oidanchor/admin/trust-marks/issue');
        $t->data['listUrl']      = Module::getModuleURL('oidanchor/admin/trust-marks');
        $t->data['csrfToken']    = $this->csrfToken();
        $t->data['logouturl']    = $authUtils->getAdminLogoutURL();
        $t->data['flash']        = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    public function issue(Request $request): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $errors   = [];
        $formData = ['trust_mark_id' => '', 'sub' => '', 'exp' => '', 'extra_claims' => ''];

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
            }

            $formData = [
                'trust_mark_id' => trim((string) $request->request->get('trust_mark_id', '')),
                'sub'           => trim((string) $request->request->get('sub', '')),
                'exp'           => trim((string) $request->request->get('exp', '')),
                'extra_claims'  => trim((string) $request->request->get('extra_claims', '')),
            ];

            $errors = (new IssuedTrustMarkValidator())->validate($formData);

            $typeRepo = $this->typeRepository();
            if (!isset($errors['trust_mark_id']) && $typeRepo->findById($formData['trust_mark_id']) === null) {
                $errors['trust_mark_id'] = 'Unknown Trust Mark type. Create it in the catalog first.';
            }

            if ($errors === []) {
                try {
                    $exp = $formData['exp'] !== '' ? time() + (int) $formData['exp'] : null;

                    $extraClaims = $formData['extra_claims'] !== ''
                        ? (json_decode($formData['extra_claims'], true) ?: [])
                        : [];

                    $issuer = new TrustMarkIssuer(
                        new FederationKeyService(Configuration::getConfig('module_oidanchor.php')),
                        $typeRepo,
                        $this->issuedRepository(),
                    );

                    $mark = $issuer->issue($formData['trust_mark_id'], $formData['sub'], $exp, $extraClaims);

                    Logger::info(sprintf(
                        'oidanchor: trust mark issued: type=%s sub=%s id=%d (admin: %s)',
                        $formData['trust_mark_id'],
                        $formData['sub'],
                        (int) $mark->id,
                        $this->getAdminUsername(),
                    ));

                    $note = $this->subordinateRepository()->exists($formData['sub'])
                        ? ''
                        : ' Note: this subject is not a registered subordinate.';

                    $this->pushFlash('success', sprintf(
                        'Trust Mark issued for "%s".%s',
                        $formData['sub'],
                        $note,
                    ));

                    return new RedirectResponse(
                        Module::getModuleURL('oidanchor/admin/trust-marks/' . (int) $mark->id . '/view'),
                    );
                } catch (Throwable $e) {
                    $errors['trust_mark_id'] = 'Issuance failed: ' . $e->getMessage();
                }
            }
        }

        $authUtils2 = new Utils\Auth();

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_form.twig');
        $t->data['title']       = 'Issue Trust Mark';
        $t->data['formData']    = $formData;
        $t->data['errors']      = $errors;
        $t->data['types']       = $this->typeRepository()->findAll();
        $t->data['actionUrl']   = Module::getModuleURL('oidanchor/admin/trust-marks/issue');
        $t->data['listUrl']     = Module::getModuleURL('oidanchor/admin/trust-marks');
        $t->data['csrfToken']   = $this->csrfToken();
        $t->data['logouturl']   = $authUtils2->getAdminLogoutURL();
        $t->data['flash']       = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils2->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    public function view(Request $request, string $id): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $mark = $this->issuedRepository()->findById((int) $id);

        if ($mark === null) {
            $this->pushFlash('error', sprintf('Trust Mark #%s not found.', $id));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        $decoded = $this->decodeForDisplay($mark->jwt);

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_view.twig');
        $t->data['mark']           = $mark;
        $t->data['decodedHeader']  = $decoded['header'];
        $t->data['decodedPayload'] = $decoded['payload'];
        $t->data['decodeNote']     = $decoded['note'];
        $t->data['listUrl']        = Module::getModuleURL('oidanchor/admin/trust-marks');
        $t->data['revokeUrl']      = Module::getModuleURL('oidanchor/admin/trust-marks/' . (int) $mark->id . '/revoke');
        $t->data['csrfToken']      = $this->csrfToken();
        $t->data['logouturl']      = $authUtils->getAdminLogoutURL();
        $t->data['flash']          = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    public function revoke(Request $request, string $id): RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        if (!$this->assertCsrf($request)) {
            $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        $issuedRepo = $this->issuedRepository();
        $mark       = $issuedRepo->findById((int) $id);

        if ($mark === null) {
            $this->pushFlash('error', sprintf('Trust Mark #%s not found.', $id));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        if ($mark->status === 'revoked') {
            $this->pushFlash('error', 'This Trust Mark is already revoked.');

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        $reason = trim((string) $request->request->get('reason', '')) ?: null;
        $issuedRepo->revoke((int) $mark->id, $reason);

        Logger::info(sprintf(
            'oidanchor: trust mark revoked: id=%d type=%s sub=%s (admin: %s)',
            (int) $mark->id,
            $mark->trustMarkId,
            $mark->sub,
            $this->getAdminUsername(),
        ));

        $this->pushFlash('success', sprintf('Trust Mark #%d revoked.', (int) $mark->id));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Decode a Trust Mark for read-only admin display: prefer the library parser, fall back to a
     * lenient base64 decode when strict parsing rejects the token (e.g. an expired or revoked mark).
     *
     * @return array{header: string, payload: string, note: ?string}
     */
    private function decodeForDisplay(string $jwt): array
    {
        try {
            $mark = (new Federation())->trustMarkFactory()->fromToken($jwt);

            return [
                'header'  => $this->pretty($mark->getHeader()),
                'payload' => $this->pretty($mark->getPayload()),
                'note'    => null,
            ];
        } catch (Throwable $e) {
            $parts = explode('.', $jwt);

            return [
                'header'  => $this->prettyFromSegment($parts[0] ?? ''),
                'payload' => $this->prettyFromSegment($parts[1] ?? ''),
                'note'    => 'Shown via lenient decode (strict parse failed: ' . $e->getMessage() . ').',
            ];
        }
    }


    /**
     * @param array<string,mixed> $data
     */
    private function pretty(array $data): string
    {
        return (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }


    private function prettyFromSegment(string $segment): string
    {
        if ($segment === '') {
            return '';
        }

        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }

        $json = json_decode($decoded, true);

        return is_array($json) ? $this->pretty($json) : $decoded;
    }


    private function typeRepository(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository($this->buildPdo());
    }


    private function issuedRepository(): IssuedTrustMarkRepository
    {
        return new IssuedTrustMarkRepository($this->buildPdo());
    }


    private function subordinateRepository(): SubordinateRepository
    {
        return new SubordinateRepository($this->buildPdo());
    }


    private function buildPdo(): PDO
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

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


    private function pushFlash(string $type, string $message): void
    {
        $session = Session::getSessionFromRequest();
        $session->setData(self::FLASH_KEY, 'msg', ['type' => $type, 'text' => $message]);
    }


    /**
     * @return array{type: string, text: string}|null
     */
    private function popFlash(): ?array
    {
        $session = Session::getSessionFromRequest();

        /** @var array{type: string, text: string}|null $flash */
        $flash = $session->getData(self::FLASH_KEY, 'msg');

        if ($flash !== null) {
            $session->deleteData(self::FLASH_KEY, 'msg');
        }

        return $flash;
    }


    private function getAdminUsername(): string
    {
        try {
            $session = Session::getSessionFromRequest();
            $authId  = $session->getAuthData('admin', 'Attributes');

            if (is_array($authId) && isset($authId['uid'][0])) {
                return (string) $authId['uid'][0];
            }
        } catch (\Throwable) {
            // Best-effort.
        }

        return 'admin';
    }
}
