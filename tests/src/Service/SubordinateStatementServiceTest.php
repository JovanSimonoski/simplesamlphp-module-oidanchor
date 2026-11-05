<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use SimpleSAML\Module\oidanchor\Service\SubordinateStatementService;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(SubordinateStatementService::class)]
final class SubordinateStatementServiceTest extends TestCase
{
    private const string SUB = 'https://leaf.example.org';

    private const array JWKS = ['keys' => [['kty' => 'EC', 'crv' => 'P-256', 'kid' => 'leaf-1', 'x' => 'x', 'y' => 'y']]];


    public function testBaseClaimShape(): void
    {
        $claims = $this->build($this->subordinate());

        $this->assertSame(self::ENTITY_ID, $claims['iss']);
        $this->assertSame(self::SUB, $claims['sub']);
        $this->assertSame(self::JWKS, $claims['jwks']);
        $this->assertSame(86400, $claims['exp'] - $claims['iat']);

        foreach (['metadata', 'metadata_policy', 'constraints', 'trust_marks'] as $claim) {
            $this->assertArrayNotHasKey($claim, $claims);
        }
    }


    public function testTrustMarksAreNeverEmittedEvenWhenTheLegacyFlagIsSet(): void
    {
        $this->assertArrayNotHasKey('trust_marks', $this->build($this->subordinate(includeTrustMarks: true)));
    }


    public function testMetadataIsIncludedOnlyWhenNonEmpty(): void
    {
        $this->assertArrayNotHasKey('metadata', $this->build($this->subordinate(metadata: [])));

        $metadata = ['openid_relying_party' => ['client_name' => 'Leaf']];
        $this->assertSame($metadata, $this->build($this->subordinate(metadata: $metadata))['metadata']);
    }


    public function testFederationWidePolicyIsMergedWithThePerSubordinatePolicy(): void
    {
        (new FederationPolicyRepository($this->pdo))->upsert('openid_relying_party', [
            'grant_types' => ['subset_of' => ['authorization_code', 'refresh_token']],
        ]);

        $claims = $this->build($this->subordinate(metadataPolicy: ['openid_relying_party' => [
            'grant_types' => ['subset_of' => ['authorization_code']],
        ]]));

        $this->assertSame(
            ['authorization_code'],
            array_values($claims['metadata_policy']['openid_relying_party']['grant_types']['subset_of']),
        );
    }


    public function testFederationWidePolicyForAnotherEntityTypeIsIgnored(): void
    {
        (new FederationPolicyRepository($this->pdo))->upsert('openid_provider', [
            'grant_types' => ['subset_of' => ['authorization_code']],
        ]);

        $this->assertArrayNotHasKey('metadata_policy', $this->build($this->subordinate()));
    }


    public function testIncompatiblePoliciesThrow(): void
    {
        (new FederationPolicyRepository($this->pdo))->upsert('openid_relying_party', [
            'token_endpoint_auth_method' => ['value' => 'private_key_jwt'],
        ]);

        $this->expectException(MetadataPolicyException::class);
        $this->build($this->subordinate(metadataPolicy: ['openid_relying_party' => [
            'token_endpoint_auth_method' => ['value' => 'client_secret_basic'],
        ]]));
    }


    public function testEffectiveConstraintsAreIncluded(): void
    {
        (new ConstraintsService($this->pdo))->setGeneral(['max_path_length' => 1]);

        $this->assertSame(['max_path_length' => 1], $this->build($this->subordinate())['constraints']);
    }


    public function testPerSubordinateAdditionalClaimsWinOverGeneralOnesButNotOverIssuerClaims(): void
    {
        $repo = new AdditionalClaimsRepository($this->pdo);
        $repo->create(AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL, 'source', 'general', false);
        $repo->create(AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL, 'general_only', 1, false);
        $repo->create(AdditionalClaimsRepository::SCOPE_SUBORDINATE, 'source', 'subordinate', false, 7);
        $repo->create(AdditionalClaimsRepository::SCOPE_SUBORDINATE, 'sub', 'https://evil.example.org', false, 7);

        $claims = $this->build($this->subordinate(id: 7));

        $this->assertSame('subordinate', $claims['source']);
        $this->assertSame(1, $claims['general_only']);
        $this->assertSame(self::SUB, $claims['sub']);
    }


    /**
     * @return array<string,mixed>
     */
    private function build(Subordinate $subordinate): array
    {
        return (new SubordinateStatementService())->buildClaims($subordinate, $this->moduleConfig(), $this->pdo);
    }


    /**
     * @param array<string,mixed>|null $metadataPolicy
     * @param array<string,mixed>|null $metadata
     */
    private function subordinate(
        ?array $metadataPolicy = null,
        ?array $metadata = null,
        bool $includeTrustMarks = false,
        ?int $id = null,
    ): Subordinate {
        return new Subordinate(
            entityId:          self::SUB,
            entityType:        'openid_relying_party',
            jwks:              self::JWKS,
            metadataPolicy:    $metadataPolicy,
            extraClaims:       null,
            status:            'active',
            registeredAt:      time(),
            updatedAt:         null,
            includeTrustMarks: $includeTrustMarks,
            id:                $id,
            metadata:          $metadata,
        );
    }
}
