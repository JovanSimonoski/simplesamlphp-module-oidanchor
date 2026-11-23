<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Entity\SubordinateStatus;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Module\oidanchor\Validation\SubordinateValidator;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(SubordinateService::class)]
final class SubordinateServiceTest extends TestCase
{
    private const string SUB = 'https://leaf.example.org';


    public function testBlockAndActivateUseTheSharedVocabulary(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB]);

        $service->block(self::SUB);
        $this->assertSame('blocked', $service->findSubordinate(self::SUB)?->status);

        $service->activate(self::SUB);
        $this->assertSame('active', $service->findSubordinate(self::SUB)?->status);
    }


    public function testStatusesOutsideTheVocabularyAreRejected(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB]);

        $this->expectException(InvalidArgumentException::class);
        $service->setStatus(self::SUB, 'suspended');
    }


    public function testEveryStatusTheApiCanSetPassesTheUiValidator(): void
    {
        $validator = new SubordinateValidator();

        foreach (SubordinateStatus::values() as $status) {
            $errors = $validator->validate(['entity_id' => self::SUB, 'status' => $status], isUpdate: true);
            $this->assertArrayNotHasKey('status', $errors, $status);
        }
    }


    public function testLegacySuspendedRowsAreMigratedToBlocked(): void
    {
        $this->service()->create(['entity_id' => self::SUB]);
        $this->pdo->exec("UPDATE oidanchor_subordinates SET status = 'suspended'");

        $this->assertSame('blocked', $this->service()->findSubordinate(self::SUB)?->status);
    }


    public function testEveryRegisteredEntityTypeIsKept(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB, 'entity_types' => ['openid_relying_party', 'openid_provider']]);

        $sub = $service->findSubordinate(self::SUB);
        $this->assertNotNull($sub);
        $this->assertSame(['openid_relying_party', 'openid_provider'], $sub->entityTypes);
        $this->assertSame('openid_relying_party', $sub->entityType);

        $service->update(self::SUB, ['entity_types' => ['federation_entity']]);
        $this->assertSame(['federation_entity'], $service->findSubordinate(self::SUB)?->entityTypes);
    }


    public function testASingleLegacyEntityTypeStillWorks(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB, 'entity_type' => 'openid_provider']);

        $this->assertSame(['openid_provider'], $service->findSubordinate(self::SUB)?->entityTypes);

        // Rows written before the entity_types column existed only have entity_type.
        $this->pdo->exec('UPDATE oidanchor_subordinates SET entity_types = NULL');
        $this->assertSame(['openid_provider'], $this->service()->findSubordinate(self::SUB)?->entityTypes);
    }


    public function testUpdateWithoutTypesLeavesThemAlone(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB, 'entity_types' => ['openid_provider', 'openid_relying_party']]);

        $service->update(self::SUB, ['description' => 'x']);

        $this->assertSame(['openid_provider', 'openid_relying_party'], $service->findSubordinate(self::SUB)?->entityTypes);
    }


    public function testCreateAndUpdateTakeTheSameDecodedRepresentation(): void
    {
        $jwks    = ['keys' => [['kty' => 'EC', 'crv' => 'P-256', 'kid' => 'k1', 'x' => 'x', 'y' => 'y']]];
        $policy  = ['openid_relying_party' => ['grant_types' => ['subset_of' => ['authorization_code']]]];
        $service = $this->service();

        $service->create(['entity_id' => self::SUB, 'jwks' => $jwks, 'metadata_policy' => $policy]);
        $created = $service->findSubordinate(self::SUB);
        $this->assertNotNull($created);
        $this->assertSame($jwks, $created->jwks);
        $this->assertSame($policy, $created->metadataPolicy);

        $metadata = ['openid_relying_party' => ['client_name' => 'Leaf']];
        $service->update(self::SUB, ['metadata' => $metadata, 'metadata_policy' => []]);
        $updated = $this->service()->findSubordinate(self::SUB);
        $this->assertNotNull($updated);
        $this->assertSame($metadata, $updated->metadata);
        $this->assertNull($updated->metadataPolicy);
        $this->assertSame($jwks, $updated->jwks);
    }


    public function testEncodedJsonStringsAreRejected(): void
    {
        $service = $this->service();
        $service->create(['entity_id' => self::SUB]);

        $this->expectException(InvalidArgumentException::class);
        $service->update(self::SUB, ['jwks' => '{"keys":[]}']);
    }


    private function service(): SubordinateService
    {
        return new SubordinateService(new SubordinateRepository($this->pdo));
    }
}
