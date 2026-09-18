<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use PDOException;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;

/**
 * Data-access layer for the subordinate registry.
 *
 * Schema is initialised (and migrated) on construction so no external migration step is needed.
 * The table was migrated to carry a surrogate `id` (the API's InternalID) while `entity_id`
 * stays unique — the admin UI and the federation endpoints still address rows by entity_id.
 */
class SubordinateRepository
{
    private const TABLE = 'oidanchor_subordinates';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    /**
     * Create the table if it does not exist yet, then apply any column migrations.
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

        $migrations = [
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN jwks TEXT',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN metadata_policy TEXT',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN extra_claims TEXT',
            "ALTER TABLE " . self::TABLE . " ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN updated_at INTEGER',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN include_trust_marks INTEGER NOT NULL DEFAULT 0',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN description TEXT',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN metadata TEXT',
            'ALTER TABLE ' . self::TABLE . ' ADD COLUMN constraints TEXT',
        ];

        foreach ($migrations as $sql) {
            try {
                $this->pdo->exec($sql);
            } catch (PDOException) {
                // Column already exists — safe to ignore.
            }
        }

        $this->migrateToSurrogateId();
    }


    /**
     * One-shot migration: rebuild the table with an autoincrement `id` primary key, preserving
     * every row (registration order becomes id order). Detected by the absence of the `id`
     * column, so it is idempotent.
     */
    private function migrateToSurrogateId(): void
    {
        $columns = $this->pdo->query('PRAGMA table_info(' . self::TABLE . ')')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if (($column['name'] ?? null) === 'id') {
                return;
            }
        }

        $this->pdo->exec(
            'CREATE TABLE ' . self::TABLE . "_new (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id           TEXT    NOT NULL UNIQUE,
                entity_type         TEXT,
                jwks                TEXT,
                metadata            TEXT,
                metadata_policy     TEXT,
                constraints         TEXT,
                extra_claims        TEXT,
                status              TEXT    NOT NULL DEFAULT 'active',
                registered_at       INTEGER NOT NULL,
                updated_at          INTEGER,
                include_trust_marks INTEGER NOT NULL DEFAULT 0,
                description         TEXT
            )",
        );

        $this->pdo->exec(
            'INSERT INTO ' . self::TABLE . '_new
                (entity_id, entity_type, jwks, metadata, metadata_policy, constraints, extra_claims,
                 status, registered_at, updated_at, include_trust_marks, description)
             SELECT entity_id, entity_type, jwks, metadata, metadata_policy, constraints, extra_claims,
                    status, registered_at, updated_at, include_trust_marks, description
             FROM ' . self::TABLE . ' ORDER BY registered_at ASC',
        );

        $this->pdo->exec('DROP TABLE ' . self::TABLE);
        $this->pdo->exec('ALTER TABLE ' . self::TABLE . '_new RENAME TO ' . self::TABLE);
    }


    /**
     * Return all registered subordinates regardless of status, ordered by registration time.
     *
     * @return Subordinate[]
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT * FROM ' . self::TABLE . ' ORDER BY registered_at ASC',
        );

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(
            static fn(array $row): Subordinate => Subordinate::fromRow($row),
            $rows,
        );
    }


    /**
     * Return entity IDs of all active subordinates, ordered by registration time.
     *
     * @return string[]
     */
    public function getAllActiveEntityIds(): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT entity_id FROM " . self::TABLE . " WHERE status = 'active' ORDER BY registered_at ASC",
        );
        $stmt->execute();

        /** @var string[] $ids */
        $ids = $stmt->fetchAll(PDO::FETCH_COLUMN);

        return $ids;
    }


    /**
     * Find a single subordinate by entity_id (any status).
     * Returns null when the entity_id is not registered.
     */
    public function findByEntityId(string $entityId): ?Subordinate
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE entity_id = ?',
        );
        $stmt->execute([$entityId]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : Subordinate::fromRow($row);
    }


    /**
     * Find a single subordinate by its surrogate id (the API's InternalID).
     */
    public function findByInternalId(int $id): ?Subordinate
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE id = ?',
        );
        $stmt->execute([$id]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : Subordinate::fromRow($row);
    }


    /**
     * Check whether an entity_id already exists in the registry.
     */
    public function exists(string $entityId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM ' . self::TABLE . ' WHERE entity_id = ?',
        );
        $stmt->execute([$entityId]);

        return $stmt->fetchColumn() !== false;
    }


    /**
     * Insert a new subordinate row and return its surrogate id.
     */
    public function create(Subordinate $sub): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (entity_id, entity_type, jwks, metadata, metadata_policy, constraints, extra_claims,
                 status, registered_at, updated_at, include_trust_marks, description)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        );

        $stmt->execute([
            $sub->entityId,
            $sub->entityType,
            $sub->jwks !== null ? json_encode($sub->jwks, JSON_UNESCAPED_SLASHES) : null,
            $sub->metadata !== null ? json_encode($sub->metadata, JSON_UNESCAPED_SLASHES) : null,
            $sub->metadataPolicy !== null ? json_encode($sub->metadataPolicy, JSON_UNESCAPED_SLASHES) : null,
            $sub->constraints !== null ? json_encode($sub->constraints, JSON_UNESCAPED_SLASHES) : null,
            $sub->extraClaims !== null ? json_encode($sub->extraClaims, JSON_UNESCAPED_SLASHES) : null,
            $sub->status,
            $sub->registeredAt,
            $sub->updatedAt,
            $sub->includeTrustMarks ? 1 : 0,
            $sub->description,
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    /**
     * Update mutable columns for an existing subordinate.
     *
     * @param array<string,mixed> $fields Associative array of column => value pairs to update (entity_id excluded).
     */
    public function update(string $entityId, array $fields): void
    {
        $allowed = [
            'entity_type', 'jwks', 'metadata', 'metadata_policy', 'constraints',
            'extra_claims', 'status', 'updated_at', 'include_trust_marks', 'description',
        ];

        $sets   = [];
        $values = [];

        foreach ($allowed as $col) {
            if (array_key_exists($col, $fields)) {
                $sets[]   = "$col = ?";
                $values[] = $fields[$col];
            }
        }

        if (empty($sets)) {
            return;
        }

        $values[] = $entityId;

        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET ' . implode(', ', $sets) . ' WHERE entity_id = ?',
        );
        $stmt->execute($values);
    }


    /**
     * Delete a subordinate row.
     */
    public function delete(string $entityId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE entity_id = ?',
        );
        $stmt->execute([$entityId]);
    }


    /**
     * Update only the status (and updated_at) for a subordinate.
     */
    public function setStatus(string $entityId, string $status): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET status = ?, updated_at = ? WHERE entity_id = ?',
        );
        $stmt->execute([$status, time(), $entityId]);
    }
}
