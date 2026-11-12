<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Database\Upsert;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkIssuerRepository;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(Upsert::class)]
final class UpsertTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->pdo->exec('CREATE TABLE t (k TEXT NOT NULL PRIMARY KEY, v TEXT, created_at INTEGER)');
    }


    public function testInsertsAMissingRow(): void
    {
        Upsert::run($this->pdo, 't', ['k' => 'a'], ['v' => 'one'], ['created_at' => 10]);

        $this->assertSame([['k' => 'a', 'v' => 'one', 'created_at' => 10]], $this->rows());
    }


    public function testUpdatesAnExistingRowButKeepsInsertOnlyColumns(): void
    {
        Upsert::run($this->pdo, 't', ['k' => 'a'], ['v' => 'one'], ['created_at' => 10]);
        Upsert::run($this->pdo, 't', ['k' => 'a'], ['v' => 'two'], ['created_at' => 99]);

        $this->assertSame([['k' => 'a', 'v' => 'two', 'created_at' => 10]], $this->rows());
    }


    public function testWithoutValuesAnExistingRowIsLeftAlone(): void
    {
        Upsert::run($this->pdo, 't', ['k' => 'a'], [], ['created_at' => 10]);
        Upsert::run($this->pdo, 't', ['k' => 'a'], [], ['created_at' => 99]);

        $this->assertSame([['k' => 'a', 'v' => null, 'created_at' => 10]], $this->rows());
    }


    public function testRepositoriesUpsertThroughIt(): void
    {
        $settings = new SettingsRepository($this->pdo);
        $settings->set('x', 1);
        $settings->set('x', 2);
        $this->assertSame(2, $settings->getInt('x'));

        $issuers = new TrustMarkIssuerRepository($this->pdo);
        $issuers->link(1, 2);
        $issuers->link(1, 2);
        $this->assertSame(
            1,
            (int) $this->pdo->query('SELECT COUNT(*) FROM oidanchor_trust_mark_type_issuers')->fetchColumn(),
        );
    }


    /**
     * @return list<array<string,mixed>>
     */
    private function rows(): array
    {
        return $this->pdo->query('SELECT k, v, created_at FROM t ORDER BY k')->fetchAll();
    }
}
