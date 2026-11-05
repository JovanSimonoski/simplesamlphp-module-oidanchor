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


    private function service(): SubordinateService
    {
        return new SubordinateService(new SubordinateRepository($this->pdo));
    }
}
