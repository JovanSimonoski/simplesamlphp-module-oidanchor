<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Database;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(PdoFactory::class)]
final class PdoFactoryTest extends TestCase
{
    public function testOneConnectionIsSharedPerRequest(): void
    {
        $config = $this->moduleConfig();

        $this->assertSame(PdoFactory::get($config), PdoFactory::get($config));
    }


    public function testConnectionsAreConfiguredConsistently(): void
    {
        $pdo = PdoFactory::get($this->moduleConfig());

        $this->assertSame(PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(PDO::ATTR_ERRMODE));
        $this->assertSame(PDO::FETCH_ASSOC, $pdo->getAttribute(PDO::ATTR_DEFAULT_FETCH_MODE));
    }


    public function testDifferentDatabasesGetDifferentConnections(): void
    {
        $a = PdoFactory::get($this->moduleConfig());
        $b = PdoFactory::get($this->moduleConfig(['database_dsn' => $this->useFileDatabase()]));

        $this->assertNotSame($a, $b);
    }


    public function testResetOpensAFreshConnection(): void
    {
        $config = $this->moduleConfig();
        $first  = PdoFactory::get($config);

        PdoFactory::reset();

        $this->assertNotSame($first, PdoFactory::get($config));
    }


    public function testUnreachableDatabaseIsReported(): void
    {
        $this->expectException(RuntimeException::class);
        PdoFactory::get($this->moduleConfig(['database_dsn' => 'sqlite:/nonexistent/dir/oidanchor.sqlite']));
    }
}
