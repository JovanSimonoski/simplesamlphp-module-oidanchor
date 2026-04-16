<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use PDOException;

/**
 * Data-access layer for the subordinate registry.
 *
 * Schema is initialised on construction so no external migration step is needed for SQLite.
 */
class SubordinateRepository
{
    private const TABLE = 'oidanchor_subordinates';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    /**
     * Create the table if it does not exist yet, and add any columns introduced
     * after the initial schema so existing databases are upgraded transparently.
     */
    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                entity_id     TEXT    NOT NULL PRIMARY KEY,
                entity_type   TEXT,
                registered_at INTEGER NOT NULL
            )',
        );

        // Migration: jwks column added when fetch endpoint was introduced.
        try {
            $this->pdo->exec('ALTER TABLE ' . self::TABLE . ' ADD COLUMN jwks TEXT');
        } catch (PDOException) {
            // Column already exists — safe to ignore.
        }
    }


    /**
     * Return every registered entity_id, ordered by registration time.
     *
     * @return string[]
     */
    public function getAllEntityIds(): array
    {
        $stmt = $this->pdo->query(
            'SELECT entity_id FROM ' . self::TABLE . ' ORDER BY registered_at ASC',
        );

        /** @var string[] $ids */
        $ids = $stmt->fetchAll(PDO::FETCH_COLUMN);

        return $ids;
    }


    /**
     * Find a single subordinate row by entity_id.
     * Returns null when the entity_id is not registered.
     *
     * @return array{entity_id: string, entity_type: string|null, jwks: string|null, registered_at: int}|null
     */
    public function findByEntityId(string $entityId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT entity_id, entity_type, jwks, registered_at
               FROM ' . self::TABLE . '
              WHERE entity_id = ?',
        );
        $stmt->execute([$entityId]);

        /** @var array{entity_id: string, entity_type: string|null, jwks: string|null, registered_at: int}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $row;
    }
}
