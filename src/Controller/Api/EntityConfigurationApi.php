<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Read-only REST API for the entity configuration, backed by EntityConfigurationService (the same
 * builder used by the signed /.well-known/openid-federation endpoint). Mutation of metadata /
 * additional-claims / authority-hints is out of scope (no backing stores yet).
 */
class EntityConfigurationApi extends ApiController
{
    /**
     * GET /entity-configuration — the entity configuration claim set as JSON.
     */
    public function get(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->claims());
    }


    /**
     * GET /entity-configuration/metadata — the metadata block of the entity configuration.
     */
    public function getMetadata(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $claims = $this->claims();

        return $this->json($claims['metadata'] ?? new \stdClass());
    }


    /**
     * GET /entity-configuration/lifetime — entity configuration lifetime in seconds.
     */
    public function getEntityConfigurationLifetime(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->moduleConfig()->getOptionalInteger('entity_configuration_lifetime', 86400) ?? 86400);
    }


    /**
     * GET /subordinates/lifetime — general subordinate statement lifetime in seconds.
     */
    public function getSubordinateLifetime(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->moduleConfig()->getOptionalInteger('subordinate_statement_lifetime', 86400) ?? 86400);
    }


    /**
     * @return array<string,mixed>
     */
    private function claims(): array
    {
        $moduleConfig = $this->moduleConfig();

        return (new EntityConfigurationService(new FederationKeyService($moduleConfig)))
            ->buildClaims($moduleConfig, $this->buildPdo());
    }
}
