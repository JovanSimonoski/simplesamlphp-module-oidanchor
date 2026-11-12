<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Validation\TrustMarkTypeValidator;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin UI controller for the Trust Mark Types catalog.
 *
 * All methods require admin authentication; state-changing methods require a valid CSRF token.
 */
class AdminTrustMarkTypes extends AdminController
{
    protected const string FLASH_KEY = 'oidanchor_tm_types_flash';


    public function list(Request $request): Template
    {
        $this->requireAdmin();

        [$typeRepo, $issuedRepo] = $this->getRepositories();

        $types = $typeRepo->findAll();

        // Active-mark counts so the admin can see which types are in use before deleting.
        $activeCounts = [];
        foreach ($types as $type) {
            $activeCounts[$type->trustMarkType] = $issuedRepo->countActiveByType($type->trustMarkType);
        }

        $t = new Template($this->config, 'oidanchor:admin_trust_mark_types_list.twig');
        $t->data['types']        = $types;
        $t->data['activeCounts'] = $activeCounts;
        $t->data['createUrl']    = Module::getModuleURL('oidanchor/admin/trust-mark-types/create');

        return $this->page($t);
    }


    public function create(Request $request): Template|RedirectResponse
    {
        $this->requireAdmin();

        $errors   = [];
        $formData = $this->emptyFormData();

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                return $this->csrfFailure('oidanchor/admin/trust-mark-types');
            }

            $formData = $this->extractFormData($request);
            [$typeRepo] = $this->getRepositories();
            $errors = (new TrustMarkTypeValidator())->validate($formData);

            if ($errors === [] && $typeRepo->exists($formData['trust_mark_type'])) {
                $errors['trust_mark_type'] = 'A Trust Mark type with this ID already exists. Use Edit to update it.';
            }

            if ($errors === []) {
                $typeRepo->create($this->toEntity($formData));

                Logger::info(sprintf(
                    'oidanchor: trust mark type created: %s (admin: %s)',
                    $formData['trust_mark_type'],
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf('Trust Mark type "%s" created.', $formData['trust_mark_type']));

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


    public function edit(Request $request, string $trustMarkType): Template|RedirectResponse
    {
        $this->requireAdmin();

        [$typeRepo] = $this->getRepositories();
        $type = $typeRepo->findById($trustMarkType);

        if ($type === null) {
            $this->pushFlash('error', sprintf('Trust Mark type "%s" not found.', $trustMarkType));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
        }

        $errors   = [];
        $formData = $this->entityToFormData($type);

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                return $this->csrfFailure('oidanchor/admin/trust-mark-types');
            }

            $formData                  = $this->extractFormData($request);
            $formData['trust_mark_type'] = $trustMarkType;
            $errors = (new TrustMarkTypeValidator())->validate($formData, isUpdate: true);

            if ($errors === []) {
                $typeRepo->update($trustMarkType, $this->toEntity($formData, $type->createdAt));

                Logger::info(sprintf(
                    'oidanchor: trust mark type updated: %s (admin: %s)',
                    $trustMarkType,
                    $this->getAdminUsername(),
                ));

                $this->pushFlash('success', sprintf('Trust Mark type "%s" updated.', $trustMarkType));

                return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
            }
        }

        return $this->renderForm(
            sprintf('Edit Trust Mark type: %s', $trustMarkType),
            true,
            $formData,
            $errors,
            Module::getModuleURL('oidanchor/admin/trust-mark-types/' . urlencode($trustMarkType) . '/edit'),
            'Save changes',
        );
    }


    public function delete(Request $request, string $trustMarkType): RedirectResponse
    {
        $this->requireAdmin();

        if (!$this->assertCsrf($request)) {
            return $this->csrfFailure('oidanchor/admin/trust-mark-types');
        }

        [$typeRepo] = $this->getRepositories();

        if ($typeRepo->findById($trustMarkType) === null) {
            $this->pushFlash('error', sprintf('Trust Mark type "%s" not found.', $trustMarkType));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
        }

        // Issued marks are intentionally left intact (status history); only the catalog entry goes.
        $typeRepo->delete($trustMarkType);

        Logger::info(sprintf(
            'oidanchor: trust mark type deleted: %s (admin: %s)',
            $trustMarkType,
            $this->getAdminUsername(),
        ));

        $this->pushFlash('success', sprintf('Trust Mark type "%s" deleted.', $trustMarkType));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-mark-types'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @return array{0: \SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository, 1: \SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository}
     */
    private function getRepositories(): array
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        $pdo          = PdoFactory::get($moduleConfig);

        return [new TrustMarkTypeRepository($pdo), new IssuedTrustMarkRepository($pdo)];
    }


    /**
     * @return array<string,string>
     */
    private function emptyFormData(): array
    {
        return [
            'trust_mark_type'  => '',
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
            'trust_mark_type'  => trim((string) $request->request->get('trust_mark_type', '')),
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
            'trust_mark_type'  => $type->trustMarkType,
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
            trustMarkType:   $formData['trust_mark_type'],
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
        $t = new Template($this->config, 'oidanchor:admin_trust_mark_types_form.twig');
        $t->data['title']       = $title;
        $t->data['isEdit']      = $isEdit;
        $t->data['formData']    = $formData;
        $t->data['errors']      = $errors;
        $t->data['actionUrl']   = $actionUrl;
        $t->data['submitLabel'] = $submitLabel;
        $t->data['listUrl']     = Module::getModuleURL('oidanchor/admin/trust-mark-types');

        return $this->page($t);
    }
}
