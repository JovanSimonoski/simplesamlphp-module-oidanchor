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
use SimpleSAML\Module\oidanchor\Entity\FederationPolicy;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Validation\MetadataPolicyValidator;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Admin UI controller for federation-wide metadata policy management.
 */
class AdminPolicies
{
    private const FLASH_KEY = 'oidanchor_policies_flash';


    public function __construct(
        protected Configuration $config,
    ) {
    }


    /**
     * List all federation-wide policies, one per entity type.
     */
    public function list(Request $request): Template
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $repo = $this->getRepository();

        $existing     = $repo->findAll();
        $existingKeys = array_map(fn(FederationPolicy $p): string => $p->entityType, $existing);
        $allTypes     = array_column(EntityTypesEnum::cases(), 'value');
        $missing      = array_values(array_diff($allTypes, $existingKeys));

        $t = new Template($this->config, 'oidanchor:admin_policies_list.twig');
        $t->data['policies']    = $existing;
        $t->data['missingTypes'] = $missing;
        $t->data['createUrl']   = Module::getModuleURL('oidanchor/admin/policies/create');
        $t->data['logouturl']   = $authUtils->getAdminLogoutURL();
        $t->data['flash']       = $this->popFlash();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    /**
     * Create a federation-wide policy - GET renders the form, POST processes it.
     */
    public function create(Request $request): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $errors   = [];
        $formData = [
            'entity_type' => trim((string) $request->query->get('entity_type', '')),
            'policy'      => '',
        ];

        if ($request->isMethod('POST')) {
            $formData  = $this->extractFormData($request);
            $repo      = $this->getRepository();
            $validator = new MetadataPolicyValidator();

            $errors = $this->validateFormData($formData, $validator);

            if (empty($errors) && $repo->findByEntityType($formData['entity_type']) !== null) {
                $errors['entity_type'] = sprintf(
                    'A federation-wide policy for "%s" already exists. Use Edit to update it.',
                    $formData['entity_type'],
                );
            }

            if (empty($errors)) {
                $decoded = json_decode($formData['policy'], true);
                $repo->upsert($formData['entity_type'], $decoded);

                Logger::info(sprintf(
                    'oidanchor: federation-wide policy created for entity type "%s" (admin: %s)',
                    $formData['entity_type'],
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf(
                    'Federation-wide policy for "%s" created.',
                    $formData['entity_type'],
                ));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/policies'));
            }
        }

        return $this->renderForm(
            $request,
            'Create federation-wide policy',
            null,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/policies/create'),
            'Create',
            false,
        );
    }


    /**
     * Edit a federation-wide policy - GET renders the pre-filled form, POST processes it.
     */
    public function edit(Request $request, string $entityType): Template|RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $repo   = $this->getRepository();
        $policy = $repo->findByEntityType($entityType);

        if ($policy === null) {
            $this->pushFlash('error', sprintf('No policy found for entity type "%s".', $entityType));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/policies'));
        }

        $errors   = [];
        $formData = [];

        if ($request->isMethod('POST')) {
            $formData              = $this->extractFormData($request);
            $formData['entity_type'] = $entityType;
            $validator             = new MetadataPolicyValidator();

            $errors = $this->validateFormData($formData, $validator, isUpdate: true);

            if (empty($errors)) {
                $decoded = json_decode($formData['policy'], true);
                $repo->upsert($entityType, $decoded);

                Logger::info(sprintf(
                    'oidanchor: federation-wide policy updated for entity type "%s" (admin: %s)',
                    $entityType,
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf(
                    'Federation-wide policy for "%s" updated.',
                    $entityType,
                ));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/policies'));
            }
        } else {
            $formData = [
                'entity_type' => $policy->entityType,
                'policy'      => json_encode($policy->policy, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            ];
        }

        return $this->renderForm(
            $request,
            sprintf('Edit federation-wide policy: %s', $entityType),
            $policy,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/policies/' . urlencode($entityType) . '/edit'),
            'Save changes',
            true,
        );
    }


    /**
     * Delete a federation-wide policy (POST only).
     */
    public function delete(Request $request, string $entityType): RedirectResponse
    {
        $authUtils = new Utils\Auth();
        $authUtils->requireAdmin();

        $repo = $this->getRepository();

        if ($repo->findByEntityType($entityType) === null) {
            $this->pushFlash('error', sprintf('No policy found for entity type "%s".', $entityType));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/policies'));
        }

        $repo->delete($entityType);

        Logger::info(sprintf(
            'oidanchor: federation-wide policy deleted for entity type "%s" (admin: %s)',
            $entityType,
            $this->getAdminUsername(),
        ));

        $this->pushFlash('success', sprintf('Federation-wide policy for "%s" deleted.', $entityType));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/policies'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function getRepository(): FederationPolicyRepository
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        return new FederationPolicyRepository($this->buildPdo($moduleConfig));
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
    private function extractFormData(Request $request): array
    {
        return [
            'entity_type' => trim((string) $request->request->get('entity_type', '')),
            'policy'      => trim((string) $request->request->get('policy', '')),
        ];
    }


    /**
     * @param array<string,string> $formData
     * @return array<string,string>
     */
    private function validateFormData(
        array $formData,
        MetadataPolicyValidator $validator,
        bool $isUpdate = false,
    ): array {
        $errors = [];

        if (!$isUpdate) {
            if (empty($formData['entity_type'])) {
                $errors['entity_type'] = 'Entity type is required.';
            } else {
                $validTypes = array_column(EntityTypesEnum::cases(), 'value');
                if (!in_array($formData['entity_type'], $validTypes, true)) {
                    $errors['entity_type'] = sprintf(
                        'Unknown entity type. Valid types: %s.',
                        implode(', ', $validTypes),
                    );
                }
            }
        }

        if (empty($formData['policy'])) {
            $errors['policy'] = 'Policy JSON is required.';
        } else {
            $entityType = $formData['entity_type'] ?? 'federation_entity';
            $err = $validator->validateEntityTypePolicy($formData['policy'], $entityType);
            if ($err !== null) {
                $errors['policy'] = $err;
            }
        }

        return $errors;
    }


    /**
     * @param array<string,string> $formData
     * @param array<string,string> $errors
     */
    private function renderForm(
        Request $request,
        string $title,
        ?FederationPolicy $policy,
        array $formData,
        array $errors,
        string $actionUrl,
        string $submitLabel,
        bool $isEdit,
    ): Template {
        $authUtils = new Utils\Auth();

        $t = new Template($this->config, 'oidanchor:admin_policies_form.twig');
        $t->data['title']       = $title;
        $t->data['policy']      = $policy;
        $t->data['formData']    = $formData;
        $t->data['errors']      = $errors;
        $t->data['actionUrl']   = $actionUrl;
        $t->data['submitLabel'] = $submitLabel;
        $t->data['isEdit']      = $isEdit;
        $t->data['entityTypes'] = array_column(EntityTypesEnum::cases(), 'value');
        $t->data['listUrl']     = Module::getModuleURL('oidanchor/admin/policies');
        $t->data['logouturl']   = $authUtils->getAdminLogoutURL();
        $t->data['flash']       = $this->popFlash();

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
