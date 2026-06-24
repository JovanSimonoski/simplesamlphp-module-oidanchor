<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\admin\Controller\Menu;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Module\oidanchor\Validation\SubordinateValidator;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Admin UI controller for subordinate management.
 *
 * All methods require admin authentication.
 */
class AdminSubordinates
{
    private const FLASH_KEY = 'oidanchor_flash';


    public function __construct(
        protected Configuration $config,
    ) {
    }


    /**
     * List all subordinates.
     */
    public function list(Request $request): Template
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $service = $this->getService();

        $subordinates = $service->findAll();

        $t = new Template($this->config, 'oidanchor:admin_subordinates_list.twig');
        $t->data['subordinates']  = $subordinates;
        $t->data['entityTypes']   = array_column(EntityTypesEnum::cases(), 'value');
        $t->data['createUrl']     = Module::getModuleURL('oidanchor/admin/subordinates/create');
        $t->data['logouturl']     = $authUtils->getAdminLogoutURL();
        $t->data['flash']         = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    /**
     * Create new subordinate — GET renders the form, POST processes it.
     */
    public function create(Request $request): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $errors   = [];
        $formData = $this->emptyFormData();

        if ($request->isMethod('POST')) {
            $formData = $this->extractFormData($request);
            $service  = $this->getService();
            $validator = new SubordinateValidator();

            $errors = $validator->validate($formData);

            if (empty($errors)) {
                if ($service->exists($formData['entity_id'])) {
                    $errors['entity_id'] = 'A subordinate with this Entity ID is already registered.';
                }
            }

            if (empty($errors)) {
                $service->create($formData);

                $adminUser = $this->getAdminUsername();
                Logger::info(sprintf(
                    'oidanchor: subordinate created: %s (admin: %s)',
                    $formData['entity_id'],
                    $adminUser,
                ));

                $this->pushFlash('success', sprintf(
                    'Subordinate "%s" registered successfully.',
                    $formData['entity_id'],
                ));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
            }
        }

        return $this->renderForm(
            $request,
            'Register new subordinate',
            null,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/subordinates/create'),
            'Register',
        );
    }


    /**
     * Edit a subordinate — GET renders the pre-filled form, POST processes it.
     */
    public function edit(Request $request, string $entityId): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $service     = $this->getService();
        $subordinate = $service->findSubordinate($entityId);

        if ($subordinate === null) {
            $this->pushFlash('error', sprintf('Subordinate "%s" not found.', $entityId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
        }

        $errors   = [];
        $formData = [];

        if ($request->isMethod('POST')) {
            $formData             = $this->extractFormData($request);
            $formData['entity_id'] = $entityId;
            $validator            = new SubordinateValidator();

            $errors = $validator->validate($formData, isUpdate: true);

            if (empty($errors)) {
                $service->update($entityId, $formData);

                $adminUser = $this->getAdminUsername();
                Logger::info(sprintf(
                    'oidanchor: subordinate updated: %s (admin: %s)',
                    $entityId,
                    $adminUser,
                ));

                $this->pushFlash('success', sprintf('Subordinate "%s" updated.', $entityId));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
            }
        } else {
            $formData = $this->subordinateToFormData($subordinate);
        }

        $encodedId = urlencode($entityId);

        return $this->renderForm(
            $request,
            sprintf('Edit subordinate: %s', $entityId),
            $subordinate,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/subordinates/' . $encodedId . '/edit'),
            'Save changes',
        );
    }


    /**
     * Delete a subordinate (POST only).
     */
    public function delete(Request $request, string $entityId): RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $service = $this->getService();

        if ($service->findSubordinate($entityId) === null) {
            $this->pushFlash('error', sprintf('Subordinate "%s" not found.', $entityId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
        }

        $service->delete($entityId);

        $adminUser = $this->getAdminUsername();
        Logger::info(sprintf(
            'oidanchor: subordinate deleted: %s (admin: %s)',
            $entityId,
            $adminUser,
        ));

        $this->pushFlash('success', sprintf('Subordinate "%s" deleted.', $entityId));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
    }


    /**
     * Set subordinate status (POST only). Expects ?status=active|suspended in query or body.
     */
    public function setStatus(Request $request, string $entityId): RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $status  = $request->request->get('status') ?? $request->query->get('status', '');
        $service = $this->getService();

        if ($service->findSubordinate($entityId) === null) {
            $this->pushFlash('error', sprintf('Subordinate "%s" not found.', $entityId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
        }

        if ($status === 'suspended') {
            $service->suspend($entityId);
            $verb = 'suspended';
        } else {
            $service->activate($entityId);
            $verb = 'activated';
        }

        $adminUser = $this->getAdminUsername();
        Logger::info(sprintf(
            'oidanchor: subordinate %s: %s (admin: %s)',
            $verb,
            $entityId,
            $adminUser,
        ));

        $this->pushFlash('success', sprintf('Subordinate "%s" %s.', $entityId, $verb));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function getService(): SubordinateService
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        return new SubordinateService(
            new SubordinateRepository($this->buildPdo($moduleConfig)),
        );
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
            'entity_id'           => '',
            'entity_type'         => '',
            'jwks'                => '',
            'metadata_policy'     => '',
            'extra_claims'        => '',
            'include_trust_marks' => '',
        ];
    }


    /**
     * @return array<string,string>
     */
    private function extractFormData(Request $request): array
    {
        return [
            'entity_id'           => trim((string) $request->request->get('entity_id', '')),
            'entity_type'         => trim((string) $request->request->get('entity_type', '')),
            'jwks'                => trim((string) $request->request->get('jwks', '')),
            'metadata_policy'     => trim((string) $request->request->get('metadata_policy', '')),
            'extra_claims'        => trim((string) $request->request->get('extra_claims', '')),
            'include_trust_marks' => $request->request->get('include_trust_marks') !== null ? '1' : '',
        ];
    }


    /**
     * @return array<string,string>
     */
    private function subordinateToFormData(Subordinate $sub): array
    {
        return [
            'entity_id'       => $sub->entityId,
            'entity_type'     => $sub->entityType ?? '',
            'jwks'            => $sub->jwks !== null
                                    ? json_encode($sub->jwks, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
            'metadata_policy' => $sub->metadataPolicy !== null
                                    ? json_encode($sub->metadataPolicy, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
            'extra_claims'    => $sub->extraClaims !== null
                                    ? json_encode($sub->extraClaims, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
            'include_trust_marks' => $sub->includeTrustMarks ? '1' : '',
        ];
    }


    /**
     * @param array<string,string> $formData
     * @param array<string,string> $errors
     */
    private function renderForm(
        Request $request,
        string $title,
        ?Subordinate $subordinate,
        array $formData,
        array $errors,
        string $actionUrl,
        string $submitLabel,
    ): Template {
        $authUtils = new Utils\Auth();

        $t = new Template($this->config, 'oidanchor:admin_subordinates_form.twig');
        $t->data['title']        = $title;
        $t->data['subordinate']  = $subordinate;
        $t->data['formData']     = $formData;
        $t->data['errors']       = $errors;
        $t->data['actionUrl']    = $actionUrl;
        $t->data['submitLabel']  = $submitLabel;
        $t->data['entityTypes']  = array_column(EntityTypesEnum::cases(), 'value');
        $t->data['listUrl']      = Module::getModuleURL('oidanchor/admin/subordinates');
        $t->data['logouturl']    = $authUtils->getAdminLogoutURL();
        $t->data['flash']        = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
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
