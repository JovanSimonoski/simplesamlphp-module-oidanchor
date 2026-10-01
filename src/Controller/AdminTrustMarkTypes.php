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
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Validation\TrustMarkTypeValidator;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin UI controller for the Trust Mark Types catalog.
 *
 * All methods require admin authentication; state-changing methods require a valid CSRF token.
 */
class AdminTrustMarkTypes
{
    private const FLASH_KEY = 'oidanchor_tm_types_flash';


    public function __construct(
        protected Configuration $config,
    ) {
    }


    public function list(Request $request): Template
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        [$typeRepo, $issuedRepo] = $this->getRepositories();

        $types = $typeRepo->findAll();

        // Active-mark counts so the admin can see which types are in use before deleting.
        $activeCounts = [];
        foreach ($types as $type) {
            $activeCounts[$type->trustMarkId] = $issuedRepo->countActiveByType($type->trustMarkId);
        }

        $t = new Template($this->config, 'oidanchor:admin_trust_mark_types_list.twig');
        $t->data['types']        = $types;
        $t->data['activeCounts'] = $activeCounts;
        $t->data['createUrl']    = Module::getModuleURL('oidanchor/admin/trust-mark-types/create');
        $t->data['csrfToken']    = $this->csrfToken();
        $t->data['logouturl']    = $authUtils->getAdminLogoutURL();
        $t->data['flash']        = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    public function create(Request $request): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $errors   = [];
        $formData = $this->emptyFormData();

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
            }

            $formData = $this->extractFormData($request);
            [$typeRepo] = $this->getRepositories();
            $errors = (new TrustMarkTypeValidator())->validate($formData);

            if ($errors === [] && $typeRepo->exists($formData['trust_mark_id'])) {
                $errors['trust_mark_id'] = 'A Trust Mark type with this ID already exists. Use Edit to update it.';
            }

            if ($errors === []) {
                $typeRepo->create($this->toEntity($formData));

                Logger::info(sprintf(
                    'oidanchor: trust mark type created: %s (admin: %s)',
                    $formData['trust_mark_id'],
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf('Trust Mark type "%s" created.', $formData['trust_mark_id']));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
            }
        }

        return $this->renderForm(
            'Create Trust Mark type',
            false,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/trust-mark-types/create'),
            'Create',
        );
    }


    public function edit(Request $request, string $trustMarkId): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        [$typeRepo] = $this->getRepositories();
        $type = $typeRepo->findById($trustMarkId);

        if ($type === null) {
            $this->pushFlash('error', sprintf('Trust Mark type "%s" not found.', $trustMarkId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
        }

        $errors   = [];
        $formData = $this->entityToFormData($type);

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
            }

            $formData                  = $this->extractFormData($request);
            $formData['trust_mark_id'] = $trustMarkId;
            $errors = (new TrustMarkTypeValidator())->validate($formData, isUpdate: true);

            if ($errors === []) {
                $typeRepo->update($trustMarkId, $this->toEntity($formData, $type->createdAt));

                Logger::info(sprintf(
                    'oidanchor: trust mark type updated: %s (admin: %s)',
                    $trustMarkId,
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf('Trust Mark type "%s" updated.', $trustMarkId));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
            }
        }

        return $this->renderForm(
            sprintf('Edit Trust Mark type: %s', $trustMarkId),
            true,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/trust-mark-types/' . urlencode($trustMarkId) . '/edit'),
            'Save changes',
        );
    }


    public function delete(Request $request, string $trustMarkId): RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        if (!$this->assertCsrf($request)) {
            $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
        }

        [$typeRepo] = $this->getRepositories();

        if ($typeRepo->findById($trustMarkId) === null) {
            $this->pushFlash('error', sprintf('Trust Mark type "%s" not found.', $trustMarkId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
        }

        // Issued marks are intentionally left intact (status history); only the catalog entry goes.
        $typeRepo->delete($trustMarkId);

        Logger::info(sprintf(
            'oidanchor: trust mark type deleted: %s (admin: %s)',
            $trustMarkId,
            $this->getAdminUsername(),
        ));

        $this->pushFlash('success', sprintf('Trust Mark type "%s" deleted.', $trustMarkId));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @return array{0: TrustMarkTypeRepository, 1: IssuedTrustMarkRepository}
     */
    private function getRepositories(): array
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        $pdo          = $this->buildPdo($moduleConfig);

        return [new TrustMarkTypeRepository($pdo), new IssuedTrustMarkRepository($pdo)];
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


    /**
     * @return array<string,string>
     */
    private function emptyFormData(): array
    {
        return [
            'trust_mark_id'    => '',
            'name'             => '',
            'description'      => '',
            'logo_uri'         => '',
            'ref_uri'          => '',
            'default_lifetime' => '',
            'extra_claims'     => '',
        ];
    }


    /**
     * @return array<string,string>
     */
    private function extractFormData(Request $request): array
    {
        return [
            'trust_mark_id'    => trim((string) $request->request->get('trust_mark_id', '')),
            'name'             => trim((string) $request->request->get('name', '')),
            'description'      => trim((string) $request->request->get('description', '')),
            'logo_uri'         => trim((string) $request->request->get('logo_uri', '')),
            'ref_uri'          => trim((string) $request->request->get('ref_uri', '')),
            'default_lifetime' => trim((string) $request->request->get('default_lifetime', '')),
            'extra_claims'     => trim((string) $request->request->get('extra_claims', '')),
        ];
    }


    /**
     * @return array<string,string>
     */
    private function entityToFormData(TrustMarkType $type): array
    {
        return [
            'trust_mark_id'    => $type->trustMarkId,
            'name'             => $type->name,
            'description'      => $type->description ?? '',
            'logo_uri'         => $type->logoUri ?? '',
            'ref_uri'          => $type->refUri ?? '',
            'default_lifetime' => $type->defaultLifetime !== null ? (string) $type->defaultLifetime : '',
            'extra_claims'     => $type->extraClaims !== null
                                    ? (string) json_encode($type->extraClaims, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
        ];
    }


    /**
     * @param array<string,string> $formData
     */
    private function toEntity(array $formData, ?int $createdAt = null): TrustMarkType
    {
        $extra = $formData['extra_claims'] !== ''
            ? json_decode($formData['extra_claims'], true)
            : null;

        return new TrustMarkType(
            trustMarkId:     $formData['trust_mark_id'],
            name:            $formData['name'],
            description:     $formData['description'] !== '' ? $formData['description'] : null,
            logoUri:         $formData['logo_uri'] !== '' ? $formData['logo_uri'] : null,
            refUri:          $formData['ref_uri'] !== '' ? $formData['ref_uri'] : null,
            defaultLifetime: $formData['default_lifetime'] !== '' ? (int) $formData['default_lifetime'] : null,
            extraClaims:     is_array($extra) ? $extra : null,
            createdAt:       $createdAt ?? time(),
            updatedAt:       $createdAt !== null ? time() : null,
        );
    }


    /**
     * @param array<string,string> $formData
     * @param array<string,string> $errors
     */
    private function renderForm(
        string $title,
        bool $isEdit,
        array $formData,
        array $errors,
        string $actionUrl,
        string $submitLabel,
    ): Template {
        $authUtils = new Utils\Auth();

        $t = new Template($this->config, 'oidanchor:admin_trust_mark_types_form.twig');
        $t->data['title']       = $title;
        $t->data['isEdit']      = $isEdit;
        $t->data['formData']    = $formData;
        $t->data['errors']      = $errors;
        $t->data['actionUrl']   = $actionUrl;
        $t->data['submitLabel'] = $submitLabel;
        $t->data['csrfToken']   = $this->csrfToken();
        $t->data['listUrl']     = Module::getModuleURL('oidanchor/admin/trust-mark-types');
        $t->data['logouturl']   = $authUtils->getAdminLogoutURL();
        $t->data['flash']       = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
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
