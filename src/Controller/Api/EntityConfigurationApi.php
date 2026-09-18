<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\EcMetadataRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for the TA's own entity configuration: the assembled document, its metadata at
 * three granularities, its additional claims, and the entity-configuration / subordinate
 * statement lifetimes.
 *
 * Writes land in the API-managed stores that EntityConfigurationService reads, so every change
 * is visible on the next request to /.well-known/openid-federation.
 */
class EntityConfigurationApi extends ApiController
{
    use AdditionalClaimsTrait;
    use MetadataDocumentTrait;

    /**
     * GET /entity-configuration — the entity configuration claim set as JSON.
     */
    public function get(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $moduleConfig = $this->moduleConfig();
        $pdo          = $this->buildPdo();

        return $this->json(
            (new EntityConfigurationService(new FederationKeyService($moduleConfig, $pdo)))
                ->buildClaims($moduleConfig, $pdo),
        );
    }


    // ---- lifetimes ---------------------------------------------------------

    /**
     * GET /entity-configuration/lifetime
     */
    public function getEntityConfigurationLifetime(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $moduleConfig = $this->moduleConfig();
        $pdo          = $this->buildPdo();

        return $this->json(
            (new EntityConfigurationService(new FederationKeyService($moduleConfig, $pdo)))
                ->lifetime($moduleConfig, $pdo),
        );
    }


    /**
     * PUT /entity-configuration/lifetime (text/plain seconds)
     */
    public function updateEntityConfigurationLifetime(Request $request): JsonResponse
    {
        return $this->writeLifetime($request, SettingsRepository::ENTITY_CONFIGURATION_LIFETIME);
    }


    /**
     * GET /subordinates/lifetime
     */
    public function getSubordinateLifetime(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json(
            $this->settings()->getInt(SettingsRepository::SUBORDINATE_STATEMENT_LIFETIME)
                ?? $this->moduleConfig()->getOptionalInteger('subordinate_statement_lifetime', 86400)
                ?? 86400,
        );
    }


    /**
     * PUT /subordinates/lifetime (text/plain seconds)
     */
    public function updateSubordinateLifetime(Request $request): JsonResponse
    {
        return $this->writeLifetime($request, SettingsRepository::SUBORDINATE_STATEMENT_LIFETIME);
    }


    // ---- metadata (three granularities) -------------------------------------

    public function getMetadata(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $moduleConfig = $this->moduleConfig();
        $pdo          = $this->buildPdo();

        // The published metadata claim: derived endpoints overlaid with the stored document.
        return $this->json(
            (new EntityConfigurationService(new FederationKeyService($moduleConfig, $pdo)))
                ->metadata($moduleConfig, $pdo),
        );
    }


    public function updateMetadata(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataReplace($request);
    }


    public function getEntityTypedMetadata(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataForType($entityType);
    }


    public function changeEntityTypedMetadata(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataPutType($request, $entityType);
    }


    public function addMetadataClaims(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataAddClaims($request, $entityType);
    }


    public function deleteEntityTypedMetadata(Request $request, string $entityType): Response
    {
        $this->requireAdmin();

        return $this->metadataDeleteType($entityType);
    }


    public function getMetadataClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataGetClaim($entityType, $claim);
    }


    public function changeMetadataClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        return $this->metadataPutClaim($request, $entityType, $claim);
    }


    public function deleteMetadataClaim(Request $request, string $entityType, string $claim): Response
    {
        $this->requireAdmin();

        return $this->metadataDeleteClaim($entityType, $claim);
    }


    // ---- additional claims --------------------------------------------------

    public function getAdditionalClaims(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsIndex(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION);
    }


    public function updateAdditionalClaims(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsReplace($request, AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION);
    }


    public function addAdditionalClaims(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsAdd($request, AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION);
    }


    public function getAdditionalClaim(Request $request, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimGet(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION, $additionalClaimsID);
    }


    public function updateAdditionalClaim(Request $request, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimUpdate(
            $request,
            AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION,
            $additionalClaimsID,
        );
    }


    public function deleteAdditionalClaim(Request $request, string $additionalClaimsID): Response
    {
        $this->requireAdmin();

        return $this->additionalClaimDelete(
            AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION,
            $additionalClaimsID,
        );
    }


    // -------------------------------------------------------------------------

    private function writeLifetime(Request $request, string $settingKey): JsonResponse
    {
        $this->requireAdmin();

        $raw = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if ($raw === '' || !ctype_digit($raw)) {
            return $this->badRequest('Request body must contain the lifetime in seconds (a non-negative integer).');
        }

        $seconds = (int) $raw;
        $this->settings()->set($settingKey, $seconds);
        Logger::info(sprintf('oidanchor: API %s set to %d', $settingKey, $seconds));

        return $this->json($seconds);
    }


    /**
     * @return array<string,array<string,mixed>>
     */
    protected function readMetadataDocument(): array
    {
        return (new EcMetadataRepository($this->buildPdo()))->all();
    }


    /**
     * @param array<string,array<string,mixed>> $document
     */
    protected function writeMetadataDocument(array $document): void
    {
        (new EcMetadataRepository($this->buildPdo()))->replaceAll($document);
        Logger::info('oidanchor: API entity configuration metadata updated');
    }
}
