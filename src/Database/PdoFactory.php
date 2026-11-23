<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Database;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;

/**
 * The module's single place for opening the database connection.
 *
 * One connection per DSN/user is kept for the request, so every controller, service and
 * repository shares it: repository schema setup runs once per request instead of once per
 * connection, a transaction spans everything that takes part in it, and SQLite does not see
 * several write-capable connections from one request competing for its lock.
 */
final class PdoFactory
{
    /** @var array<string,\PDO> */
    private static array $connections = [];


    /**
     * @throws \RuntimeException When the database cannot be reached.
     */
    public static function get(Configuration $moduleConfig): PDO
    {
        $dsn      = $moduleConfig->getString('database_dsn');
        $username = $moduleConfig->getOptionalString('database_username', null);
        $key      = $dsn . "\0" . $username;

        if (isset(self::$connections[$key])) {
            return self::$connections[$key];
        }

        try {
            return self::$connections[$key] = new PDO(
                $dsn,
                $username,
                $moduleConfig->getOptionalString('database_password', null),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ],
            );
        } catch (PDOException $e) {
            throw new RuntimeException('oidanchor: cannot connect to database: ' . $e->getMessage(), 0, $e);
        }
    }


    /**
     * Drop the kept connections (tests, long-running workers).
     */
    public static function reset(): void
    {
        self::$connections = [];
    }
}
