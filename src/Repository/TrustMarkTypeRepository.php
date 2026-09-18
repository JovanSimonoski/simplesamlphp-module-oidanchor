<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;

/**
 * Data-access layer for the catalog of Trust Mark Types the TA is willing to issue.
 *
 * Schema is initialised (and migrated) on construction so no external migration step is needed.
 * The table gained a surrogate `id` (the API's InternalID); `trust_mark_id` (the type URL)
 * remains unique and is still the key used by the admin UI and by issuance.
 */
class TrustMarkTypeRepository
{
    private const TABLE = 'oidanchor_trust_mark_types';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                trust_mark_id    TEXT    NOT NULL PRIMARY KEY,
                name             TEXT    NOT NULL,
                description      TEXT,
                logo_uri         TEXT,
                ref_uri          TEXT,
                default_lifetime INTEGER,
                extra_claims     TEXT,
                created_at       INTEGER NOT NULL,
                updated_at       INTEGER
            )',
        );

        $this->migrateToSurrogateId();
    }


    /**
     * One-shot migration: rebuild the table with an autoincrement `id` primary key, preserving
     * every row. Detected by the absence of the `id` column, so it is idempotent.
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
            'CREATE TABLE ' . self::TABLE . '_new (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                trust_mark_id    TEXT    NOT NULL UNIQUE,
                name             TEXT    NOT NULL,
                description      TEXT,
                logo_uri         TEXT,
                ref_uri          TEXT,
                default_lifetime INTEGER,
                extra_claims     TEXT,
                created_at       INTEGER NOT NULL,
                updated_at       INTEGER
            )',
        );

        $this->pdo->exec(
            'INSERT INTO ' . self::TABLE . '_new
                (trust_mark_id, name, description, logo_uri, ref_uri, default_lifetime, extra_claims, created_at, updated_at)
             SELECT trust_mark_id, name, description, logo_uri, ref_uri, default_lifetime, extra_claims, created_at, updated_at
             FROM ' . self::TABLE . ' ORDER BY created_at ASC',
        );

        $this->pdo->exec('DROP TABLE ' . self::TABLE);
        $this->pdo->exec('ALTER TABLE ' . self::TABLE . '_new RENAME TO ' . self::TABLE);
    }


    /**
     * @return TrustMarkType[]
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT * FROM ' . self::TABLE . ' ORDER BY name ASC',
        );

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(
            static fn(array $row): TrustMarkType => TrustMarkType::fromRow($row),
            $rows,
        );
    }


    /**
     * Find by the type identifier URL (used by the admin UI and by issuance).
     */
    public function findById(string $trustMarkId): ?TrustMarkType
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE trust_mark_id = ?',
        );
        $stmt->execute([$trustMarkId]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : TrustMarkType::fromRow($row);
    }


    /**
     * Find by the surrogate id (the API's InternalID).
     */
    public function findByInternalId(int $id): ?TrustMarkType
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE id = ?',
        );
        $stmt->execute([$id]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : TrustMarkType::fromRow($row);
    }


    public function exists(string $trustMarkId): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM ' . self::TABLE . ' WHERE trust_mark_id = ?',
        );
        $stmt->execute([$trustMarkId]);

        return $stmt->fetchColumn() !== false;
    }


    /**
     * Insert a type and return its surrogate id.
     */
    public function create(TrustMarkType $type): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (trust_mark_id, name, description, logo_uri, ref_uri, default_lifetime, extra_claims, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        );

        $stmt->execute([
            $type->trustMarkId,
            $type->name,
            $type->description,
            $type->logoUri,
            $type->refUri,
            $type->defaultLifetime,
            $type->extraClaims !== null ? json_encode($type->extraClaims, JSON_UNESCAPED_SLASHES) : null,
            $type->createdAt,
            $type->updatedAt,
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    public function update(string $trustMarkId, TrustMarkType $type): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . '
                SET name = ?, description = ?, logo_uri = ?, ref_uri = ?,
                    default_lifetime = ?, extra_claims = ?, updated_at = ?
             WHERE trust_mark_id = ?',
        );

        $stmt->execute([
            $type->name,
            $type->description,
            $type->logoUri,
            $type->refUri,
            $type->defaultLifetime,
            $type->extraClaims !== null ? json_encode($type->extraClaims, JSON_UNESCAPED_SLASHES) : null,
            time(),
            $trustMarkId,
        ]);
    }


    public function delete(string $trustMarkId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE trust_mark_id = ?',
        );
        $stmt->execute([$trustMarkId]);
    }
}
