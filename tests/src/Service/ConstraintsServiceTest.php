<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(ConstraintsService::class)]
final class ConstraintsServiceTest extends TestCase
{
    public function testMaxPathLengthAcceptsNonNegativeIntegers(): void
    {
        $this->assertSame(0, ConstraintsService::validateMaxPathLength(0));
        $this->assertSame(3, ConstraintsService::validateMaxPathLength(3));
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function invalidMaxPathLengths(): array
    {
        return ['negative' => [-1], 'string' => ['2'], 'float' => [1.5], 'null' => [null]];
    }


    #[DataProvider('invalidMaxPathLengths')]
    public function testMaxPathLengthRejectsInvalidValues(mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        ConstraintsService::validateMaxPathLength($value);
    }


    public function testNamingConstraintsKeepsOnlyKnownMembers(): void
    {
        $this->assertSame(
            ['permitted' => ['.example.org'], 'excluded' => ['.bad.example.org']],
            ConstraintsService::validateNamingConstraints([
                'permitted' => ['.example.org'],
                'excluded'  => ['.bad.example.org'],
                'other'     => 'ignored',
            ]),
        );
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function invalidNamingConstraints(): array
    {
        return [
            'not an object'       => ['.example.org'],
            'permitted is object' => [['permitted' => ['a' => '.example.org']]],
            'permitted is string' => [['permitted' => '.example.org']],
            'empty subtree'       => [['excluded' => ['  ']]],
            'non-string subtree'  => [['permitted' => [42]]],
        ];
    }


    #[DataProvider('invalidNamingConstraints')]
    public function testNamingConstraintsRejectsInvalidValues(mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        ConstraintsService::validateNamingConstraints($value);
    }


    public function testAllowedEntityTypesDeduplicates(): void
    {
        $this->assertSame(
            ['openid_provider', 'openid_relying_party'],
            ConstraintsService::validateAllowedEntityTypes(['openid_provider', 'openid_relying_party', 'openid_provider']),
        );
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function invalidAllowedEntityTypes(): array
    {
        return [
            'string'       => ['openid_provider'],
            'object'       => [['a' => 'openid_provider']],
            'empty string' => [['']],
            'non-string'   => [[1]],
        ];
    }


    #[DataProvider('invalidAllowedEntityTypes')]
    public function testAllowedEntityTypesRejectsInvalidValues(mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        ConstraintsService::validateAllowedEntityTypes($value);
    }


    public function testValidateDispatchesPerMemberAndAllowsUnknownMembers(): void
    {
        $service = new ConstraintsService($this->pdo);

        $service->validate(['max_path_length' => 1, 'custom_constraint' => 'anything']);

        $this->expectException(InvalidArgumentException::class);
        $service->validate(['max_path_length' => -1]);
    }


    public function testEffectiveIsNullWhenNothingConfigured(): void
    {
        $this->assertNull((new ConstraintsService($this->pdo))->effective($this->subordinate(null)));
    }


    public function testEffectiveOverlaysSubordinateConstraintsOnGeneralOnes(): void
    {
        $service = new ConstraintsService($this->pdo);
        $service->setGeneral(['max_path_length' => 2, 'allowed_entity_types' => ['openid_provider']]);

        $this->assertSame(
            ['max_path_length' => 0, 'allowed_entity_types' => ['openid_provider']],
            $service->effective($this->subordinate(['max_path_length' => 0])),
        );
    }


    /**
     * @param array<string,mixed>|null $constraints
     */
    private function subordinate(?array $constraints): Subordinate
    {
        return new Subordinate(
            entityId:       'https://leaf.example.org',
            entityType:     'openid_relying_party',
            jwks:           null,
            metadataPolicy: null,
            extraClaims:    null,
            status:         'active',
            registeredAt:   time(),
            updatedAt:      null,
            constraints:    $constraints,
        );
    }
}
