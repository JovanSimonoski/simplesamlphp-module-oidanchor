<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor;

use PDO;
use PHPUnit\Framework\TestCase as BaseTestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Logger\LoggingHandlerInterface;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;

/**
 * Shared fixtures: an in-memory SQLite database per test, a module configuration with a
 * generated RSA signing key, and a silent SSP log handler.
 */
abstract class TestCase extends BaseTestCase
{
    protected const string ENTITY_ID = 'https://ta.example.org';


    private static ?string $keyFile = null;

    protected PDO $pdo;


    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:', null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        Logger::setLoggingHandler(new class (Configuration::loadFromArray([])) implements LoggingHandlerInterface {
            public function __construct(Configuration $config)
            {
            }


            public function log(int $level, string $string): void
            {
            }


            public function setLogFormat(string $format): void
            {
            }
        });
    }


    protected function tearDown(): void
    {
        Configuration::clearInternalState();
    }


    /**
     * @param array<string,mixed> $overrides
     */
    protected function moduleConfig(array $overrides = []): Configuration
    {
        return Configuration::loadFromArray($overrides + [
            'entity_id'        => self::ENTITY_ID,
            'base_url'         => self::ENTITY_ID,
            'signing_key_file' => self::keyFile(),
            'database_dsn'     => 'sqlite::memory:',
        ]);
    }


    /**
     * Register a module configuration for code that reads Configuration::getConfig('module_oidanchor.php').
     *
     * @param array<string,mixed> $overrides
     */
    protected function preloadModuleConfig(array $overrides = []): Configuration
    {
        $config = $this->moduleConfig($overrides);
        Configuration::setPreLoadedConfig($config, 'module_oidanchor.php');

        return $config;
    }


    protected function keys(?Configuration $config = null): FederationKeyService
    {
        return new FederationKeyService($config ?? $this->moduleConfig(), $this->pdo);
    }


    /**
     * Decode a compact JWS without verifying it.
     *
     * @return array{header: array<string,mixed>, payload: array<string,mixed>}
     */
    protected static function decodeJwt(string $jwt): array
    {
        $parts = explode('.', $jwt);
        self::assertCount(3, $parts, 'Not a compact JWS.');

        $decode = static fn(string $segment): array => (array) json_decode(
            (string) base64_decode(strtr($segment, '-_', '+/')),
            true,
        );

        return ['header' => $decode($parts[0]), 'payload' => $decode($parts[1])];
    }


    /**
     * A PEM RSA private key, generated once per test run.
     */
    private static function keyFile(): string
    {
        if (self::$keyFile !== null) {
            return self::$keyFile;
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);

        $file = tempnam(sys_get_temp_dir(), 'oidanchor-test-key-');
        self::assertIsString($file);
        file_put_contents($file, $pem);
        register_shutdown_function(static fn() => @unlink($file));

        return self::$keyFile = $file;
    }
}
