<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * Trust Mark Owners: entities that own a Trust Mark Type and may delegate its issuance.
 *
 * A type has at most one owner (`oidanchor_trust_mark_type_owner`), which carries the
 * delegation JWT the TA presents when it issues marks of a type it does not own.
 */
class TrustMarkOwnerRepository
{
    private const TABLE = 'oidanchor_trust_mark_owners';
    private const LINK_TABLE = 'oidanchor_trust_mark_type_owner';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id   TEXT    NOT NULL UNIQUE,
                jwks        TEXT    NOT NULL,
                description TEXT,
                created_at  INTEGER NOT NULL
            )',
        );

        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::LINK_TABLE . ' (
                trust_mark_type_id INTEGER NOT NULL PRIMARY KEY,
                owner_id           INTEGER NOT NULL,
                delegation_jwt     TEXT,
                created_at         INTEGER NOT NULL
            )',
        );
    }


    // ---- owners -----------------------------------------------------------

    /**
     * @return list<array<string,mixed>>
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query('SELECT * FROM ' . self::TABLE . ' ORDER BY id ASC');

        return array_map(
            static fn(array $row): array => self::toApi($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * @return array<string,mixed>|null
     */
    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM ' . self::TABLE . ' WHERE id = ?');
        $stmt->execute([$id]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::toApi($row);
    }


    /**
     * @return array<string,mixed>|null
     */
    public function findByEntityId(string $entityId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM ' . self::TABLE . ' WHERE entity_id = ?');
        $stmt->execute([$entityId]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::toApi($row);
    }


    /**
     * @param array<string,mixed> $jwks
     * @throws InvalidArgumentException When the entity_id is already registered as an owner.
     */
    public function create(string $entityId, array $jwks, ?string $description): int
    {
        if ($this->findByEntityId($entityId) !== null) {
            throw new InvalidArgumentException(sprintf('Trust mark owner "%s" already exists.', $entityId));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (entity_id, jwks, description, created_at) VALUES (?, ?, ?, ?)',
        );
        $stmt->execute([$entityId, json_encode($jwks, JSON_UNESCAPED_SLASHES), $description, time()]);

        return (int) $this->pdo->lastInsertId();
    }


    /**
     * @param array<string,mixed> $jwks
     */
    public function update(int $id, string $entityId, array $jwks, ?string $description): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET entity_id = ?, jwks = ?, description = ? WHERE id = ?',
        );
        $stmt->execute([$entityId, json_encode($jwks, JSON_UNESCAPED_SLASHES), $description, $id]);
    }


    public function delete(int $id): void
    {
        $this->pdo->prepare('DELETE FROM ' . self::LINK_TABLE . ' WHERE owner_id = ?')->execute([$id]);
        $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?')->execute([$id]);
    }


    // ---- type ↔ owner links ------------------------------------------------

    /**
     * The owner of a type, with the delegation JWT, or null.
     *
     * @return array<string,mixed>|null
     */
    public function findOwnerOfType(int $trustMarkTypeId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT o.*, l.delegation_jwt
             FROM ' . self::LINK_TABLE . ' l
             JOIN ' . self::TABLE . ' o ON o.id = l.owner_id
             WHERE l.trust_mark_type_id = ?',
        );
        $stmt->execute([$trustMarkTypeId]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }

        $owner = self::toApi($row);
        if ($row['delegation_jwt'] !== null) {
            $owner['delegation_jwt'] = (string) $row['delegation_jwt'];
        }

        return $owner;
    }


    public function setOwnerOfType(int $trustMarkTypeId, int $ownerId, ?string $delegationJwt): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::LINK_TABLE . ' (trust_mark_type_id, owner_id, delegation_jwt, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(trust_mark_type_id) DO UPDATE SET
                 owner_id       = excluded.owner_id,
                 delegation_jwt = excluded.delegation_jwt',
        );
        $stmt->execute([$trustMarkTypeId, $ownerId, $delegationJwt, time()]);
    }


    public function unsetOwnerOfType(int $trustMarkTypeId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::LINK_TABLE . ' WHERE trust_mark_type_id = ?');
        $stmt->execute([$trustMarkTypeId]);
    }


    /**
     * The types owned by an owner.
     *
     * @return list<int>
     */
    public function typeIdsOfOwner(int $ownerId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT trust_mark_type_id FROM ' . self::LINK_TABLE . ' WHERE owner_id = ? ORDER BY trust_mark_type_id',
        );
        $stmt->execute([$ownerId]);

        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }


    public function unlinkOwnerType(int $ownerId, int $trustMarkTypeId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::LINK_TABLE . ' WHERE owner_id = ? AND trust_mark_type_id = ?',
        );
        $stmt->execute([$ownerId, $trustMarkTypeId]);
    }


    /**
     * Owners keyed by trust mark type URL — the source of the `trust_mark_owners` claim.
     *
     * @return array<string,array{entity_id: string, jwks: array<string,mixed>}>
     */
    public function ownersByTrustMarkType(): array
    {
        $stmt = $this->pdo->query(
            'SELECT t.trust_mark_id, o.entity_id, o.jwks
             FROM ' . self::LINK_TABLE . ' l
             JOIN ' . self::TABLE . ' o ON o.id = l.owner_id
             JOIN oidanchor_trust_mark_types t ON t.id = l.trust_mark_type_id
             ORDER BY t.trust_mark_id',
        );

        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $jwks = json_decode((string) $row['jwks'], true);
            $out[(string) $row['trust_mark_id']] = [
                'entity_id' => (string) $row['entity_id'],
                'jwks'      => is_array($jwks) ? $jwks : ['keys' => []],
            ];
        }

        return $out;
    }


    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function toApi(array $row): array
    {
        $jwks = json_decode((string) $row['jwks'], true);

        $out = [
            'id'        => (int) $row['id'],
            'entity_id' => (string) $row['entity_id'],
            'jwks'      => is_array($jwks) ? $jwks : ['keys' => []],
        ];

        if (($row['description'] ?? null) !== null) {
            $out['description'] = (string) $row['description'];
        }

        return $out;
    }
}
