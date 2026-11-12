<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Entity\SubordinateStatus;
use SimpleSAML\Module\oidanchor\Repository\SubordinateEventRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Module\oidanchor\Validation\SubordinateValidator;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin UI controller for subordinate management.
 *
 * All methods require admin authentication; state-changing methods require a valid CSRF token.
 */
class AdminSubordinates extends AdminController
{
    protected const string FLASH_KEY = 'oidanchor_flash';


    /**
     * List all subordinates.
     */
    public function list(Request $request): Template
    {
        $this->requireAdmin();

        $service = $this->getService();

        $subordinates = $service->findAll();

        $t = new Template($this->config, 'oidanchor:admin_subordinates_list.twig');
        $t->data['subordinates']  = $subordinates;
        $t->data['entityTypes']   = array_column(EntityTypesEnum::cases(), 'value');
        $t->data['createUrl']     = Module::getModuleURL('oidanchor/admin/subordinates/create');

        return $this->page($t);
    }


    /**
     * Create new subordinate — GET renders the form, POST processes it.
     */
    public function create(Request $request): Template|RedirectResponse
    {
        $this->requireAdmin();

        $errors   = [];
        $formData = $this->emptyFormData();

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                return $this->csrfFailure('oidanchor/admin/subordinates');
            }

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
                $service->create($this->toServiceData($formData));

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
        $this->requireAdmin();

        $service     = $this->getService();
        $subordinate = $service->findSubordinate($entityId);

        if ($subordinate === null) {
            $this->pushFlash('error', sprintf('Subordinate "%s" not found.', $entityId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
        }

        $errors   = [];
        $formData = [];

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                return $this->csrfFailure('oidanchor/admin/subordinates');
            }

            $formData             = $this->extractFormData($request);
            $formData['entity_id'] = $entityId;
            $validator            = new SubordinateValidator();

            $errors = $validator->validate($formData, isUpdate: true);

            if (empty($errors)) {
                $service->update($entityId, $this->toServiceData($formData));

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
        $this->requireAdmin();

        if (!$this->assertCsrf($request)) {
            return $this->csrfFailure('oidanchor/admin/subordinates');
        }

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
     * Set subordinate status (POST only). Expects status=active|blocked in the body.
     */
    public function setStatus(Request $request, string $entityId): RedirectResponse
    {
        $this->requireAdmin();

        if (!$this->assertCsrf($request)) {
            return $this->csrfFailure('oidanchor/admin/subordinates');
        }

        $status  = (string) $request->request->get('status', '');
        $service = $this->getService();

        if ($service->findSubordinate($entityId) === null) {
            $this->pushFlash('error', sprintf('Subordinate "%s" not found.', $entityId));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
        }

        if ($status === SubordinateStatus::Blocked->value) {
            $service->block($entityId);
            $verb = 'blocked';
        } elseif ($status === SubordinateStatus::Active->value) {
            $service->activate($entityId);
            $verb = 'activated';
        } else {
            $this->pushFlash('error', sprintf('Invalid status "%s".', $status));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/subordinates'));
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
        $pdo          = PdoFactory::get($moduleConfig);

        // Pass the event repository so UI mutations also land in the audit trail served by
        // GET /api/v1/admin/subordinates/{id}/history.
        return new SubordinateService(
            new SubordinateRepository($pdo),
            new SubordinateEventRepository($pdo),
        );
    }


    /**
     * @return array<string,mixed>
     */
    private function emptyFormData(): array
    {
        return [
            'entity_id'           => '',
            'entity_types'        => [],
            'jwks'                => '',
            'metadata_policy'     => '',
            'extra_claims'        => '',
        ];
    }


    /**
     * @return array<string,mixed>
     */
    private function extractFormData(Request $request): array
    {
        return [
            'entity_id'           => trim((string) $request->request->get('entity_id', '')),
            'entity_types'        => array_values(array_filter(
                array_map('strval', $request->request->all('entity_types')),
                static fn(string $t): bool => trim($t) !== '',
            )),
            'jwks'                => trim((string) $request->request->get('jwks', '')),
            'metadata_policy'     => trim((string) $request->request->get('metadata_policy', '')),
            'extra_claims'        => trim((string) $request->request->get('extra_claims', '')),
        ];
    }


    /**
     * The form keeps JSON fields as text (to re-render what the admin typed); the service takes
     * them decoded. Called after validation, so the text is valid JSON or empty.
     *
     * @param array<string,mixed> $formData
     * @return array<string,mixed>
     */
    private function toServiceData(array $formData): array
    {
        foreach (['jwks', 'metadata_policy', 'extra_claims'] as $field) {
            $raw = trim((string) ($formData[$field] ?? ''));
            $formData[$field] = $raw !== '' ? json_decode($raw, true) : null;
        }

        return $formData;
    }


    /**
     * @return array<string,mixed>
     */
    private function subordinateToFormData(Subordinate $sub): array
    {
        return [
            'entity_id'       => $sub->entityId,
            'entity_types'    => $sub->entityTypes,
            'jwks'            => $sub->jwks !== null
                                    ? json_encode($sub->jwks, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
            'metadata_policy' => $sub->metadataPolicy !== null
                                    ? json_encode($sub->metadataPolicy, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
            'extra_claims'    => $sub->extraClaims !== null
                                    ? json_encode($sub->extraClaims, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                                    : '',
        ];
    }


    /**
     * @param array<string,mixed> $formData
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
        $t = new Template($this->config, 'oidanchor:admin_subordinates_form.twig');
        $t->data['title']        = $title;
        $t->data['subordinate']  = $subordinate;
        $t->data['formData']     = $formData;
        $t->data['errors']       = $errors;
        $t->data['actionUrl']    = $actionUrl;
        $t->data['submitLabel']  = $submitLabel;
        $t->data['entityTypes']  = array_column(EntityTypesEnum::cases(), 'value');
        $t->data['listUrl']      = Module::getModuleURL('oidanchor/admin/subordinates');

        return $this->page($t);
    }
}
