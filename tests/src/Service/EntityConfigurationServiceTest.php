<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\AuthorityHintRepository;
use SimpleSAML\Module\oidanchor\Repository\EcMetadataRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(EntityConfigurationService::class)]
final class EntityConfigurationServiceTest extends TestCase
{
    public function testBaseClaimShape(): void
    {
        $keys   = $this->keys();
        $claims = (new EntityConfigurationService($keys))->buildClaims($this->moduleConfig(), $this->pdo);

        $this->assertSame(self::ENTITY_ID, $claims['iss']);
        $this->assertSame(self::ENTITY_ID, $claims['sub']);
        $this->assertSame(86400, $claims['exp'] - $claims['iat']);
        $this->assertContains($keys->kid(), array_column($claims['jwks']['keys'], 'kid'));

        // Optional claims are omitted when nothing is configured.
        foreach (['authority_hints', 'trust_marks', 'trust_mark_issuers', 'trust_mark_owners', 'crit'] as $claim) {
            $this->assertArrayNotHasKey($claim, $claims);
        }
    }


    public function testFederationEntityEndpointsAreDerivedFromTheBaseUrl(): void
    {
        $claims = (new EntityConfigurationService($this->keys()))->buildClaims($this->moduleConfig(), $this->pdo);

        $this->assertSame([
            'federation_fetch_endpoint'             => self::ENTITY_ID . '/federation/fetch',
            'federation_list_endpoint'              => self::ENTITY_ID . '/federation/list',
            'federation_resolve_endpoint'           => self::ENTITY_ID . '/resolve',
            'federation_trust_mark_status_endpoint' => self::ENTITY_ID . '/trust_mark_status',
        ], $claims['metadata']['federation_entity']);
    }


    public function testStoredMetadataOverridesDerivedValues(): void
    {
        (new EcMetadataRepository($this->pdo))->upsert('federation_entity', [
            'federation_list_endpoint' => 'https://list.example.org',
            'organization_name'        => 'Example TA',
        ]);

        $metadata = (new EntityConfigurationService($this->keys()))
            ->buildClaims($this->moduleConfig(), $this->pdo)['metadata']['federation_entity'];

        $this->assertSame('https://list.example.org', $metadata['federation_list_endpoint']);
        $this->assertSame('Example TA', $metadata['organization_name']);
        $this->assertSame(self::ENTITY_ID . '/federation/fetch', $metadata['federation_fetch_endpoint']);
    }


    public function testStoredLifetimeTakesPrecedenceOverConfig(): void
    {
        $config = $this->moduleConfig(['entity_configuration_lifetime' => 7200]);
        $claims = (new EntityConfigurationService($this->keys($config)))->buildClaims($config, $this->pdo);
        $this->assertSame(7200, $claims['exp'] - $claims['iat']);

        (new SettingsRepository($this->pdo))->set(SettingsRepository::ENTITY_CONFIGURATION_LIFETIME, 600);
        $claims = (new EntityConfigurationService($this->keys($config)))->buildClaims($config, $this->pdo);
        $this->assertSame(600, $claims['exp'] - $claims['iat']);
    }


    public function testStoredAuthorityHintsTakePrecedenceOverConfig(): void
    {
        $config  = $this->moduleConfig(['authority_hints' => ['https://config-superior.example.org']]);
        $service = new EntityConfigurationService($this->keys($config));

        $this->assertSame(['https://config-superior.example.org'], $service->buildClaims($config, $this->pdo)['authority_hints']);

        (new AuthorityHintRepository($this->pdo))->create('https://stored-superior.example.org', null);
        $this->assertSame(['https://stored-superior.example.org'], $service->buildClaims($config, $this->pdo)['authority_hints']);
    }


    public function testAdditionalClaimsAreAddedButNeverOverrideIssuerClaims(): void
    {
        $repo = new AdditionalClaimsRepository($this->pdo);
        $repo->create(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION, 'iss', 'https://evil.example.org', false);
        $repo->create(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION, 'policy_uri', 'https://ta.example.org/policy', false);
        $repo->create(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION, 'custom_critical', true, true);

        $claims = (new EntityConfigurationService($this->keys()))->buildClaims($this->moduleConfig(), $this->pdo);

        $this->assertSame(self::ENTITY_ID, $claims['iss']);
        $this->assertSame('https://ta.example.org/policy', $claims['policy_uri']);
        $this->assertTrue($claims['custom_critical']);
        $this->assertSame(['custom_critical'], $claims['crit']);
    }
}
