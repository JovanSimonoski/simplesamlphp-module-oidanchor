<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * Trust Mark Issuers: entities authorised to issue marks of a given Trust Mark Type.
 *
 * Issuers are global rows linked many-to-many to types; the links drive the
 * `trust_mark_issuers` claim of the TA's entity configuration.
 */
class TrustMarkIssuerRepository
{
    private const TABLE = 'oidanchor_trust_mark_issuers';
    private const LINK_TABLE = 'oidanchor_trust_mark_type_issuers';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer      TEXT    NOT NULL UNIQUE,
                description TEXT,
                created_at  INTEGER NOT NULL
            )',
        );

        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::LINK_TABLE . ' (
                trust_mark_type_id INTEGER NOT NULL,
                issuer_id          INTEGER NOT NULL,
                created_at         INTEGER NOT NULL,
                PRIMARY KEY (trust_mark_type_id, issuer_id)
            )',
        );
    }


    // ---- issuers ----------------------------------------------------------

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
    public function findByIssuer(string $issuer): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM ' . self::TABLE . ' WHERE issuer = ?');
        $stmt->execute([$issuer]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::toApi($row);
    }


    /**
     * @throws InvalidArgumentException When the issuer is already registered.
     */
    public function create(string $issuer, ?string $description): int
    {
        if ($this->findByIssuer($issuer) !== null) {
            throw new InvalidArgumentException(sprintf('Trust mark issuer "%s" already exists.', $issuer));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (issuer, description, created_at) VALUES (?, ?, ?)',
        );
        $stmt->execute([$issuer, $description, time()]);

        return (int) $this->pdo->lastInsertId();
    }


    public function update(int $id, string $issuer, ?string $description): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET issuer = ?, description = ? WHERE id = ?',
        );
        $stmt->execute([$issuer, $description, $id]);
    }


    public function delete(int $id): void
    {
        $this->pdo->prepare('DELETE FROM ' . self::LINK_TABLE . ' WHERE issuer_id = ?')->execute([$id]);
        $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?')->execute([$id]);
    }


    // ---- type ↔ issuer links -----------------------------------------------

    /**
     * Issuer rows linked to a type.
     *
     * @return list<array<string,mixed>>
     */
    public function issuersOfType(int $trustMarkTypeId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT i.* FROM ' . self::LINK_TABLE . ' l
             JOIN ' . self::TABLE . ' i ON i.id = l.issuer_id
             WHERE l.trust_mark_type_id = ?
             ORDER BY i.id ASC',
        );
        $stmt->execute([$trustMarkTypeId]);

        return array_map(
            static fn(array $row): array => self::toApi($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * @return list<int>
     */
    public function typeIdsOfIssuer(int $issuerId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT trust_mark_type_id FROM ' . self::LINK_TABLE . ' WHERE issuer_id = ? ORDER BY trust_mark_type_id',
        );
        $stmt->execute([$issuerId]);

        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }


    public function link(int $trustMarkTypeId, int $issuerId): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::LINK_TABLE . ' (trust_mark_type_id, issuer_id, created_at)
             VALUES (?, ?, ?)
             ON CONFLICT(trust_mark_type_id, issuer_id) DO NOTHING',
        );
        $stmt->execute([$trustMarkTypeId, $issuerId, time()]);
    }


    public function unlink(int $trustMarkTypeId, int $issuerId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::LINK_TABLE . ' WHERE trust_mark_type_id = ? AND issuer_id = ?',
        );
        $stmt->execute([$trustMarkTypeId, $issuerId]);
    }


    public function unlinkAllOfType(int $trustMarkTypeId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::LINK_TABLE . ' WHERE trust_mark_type_id = ?');
        $stmt->execute([$trustMarkTypeId]);
    }


    public function unlinkAllOfIssuer(int $issuerId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::LINK_TABLE . ' WHERE issuer_id = ?');
        $stmt->execute([$issuerId]);
    }


    /**
     * Every catalogued trust mark type mapped to the entity IDs of its authorised issuers.
     * Types with no explicit issuers map to an empty list (the caller substitutes the TA).
     *
     * @return array<string,list<string>>
     */
    public function issuersByTrustMarkType(): array
    {
        $types = $this->pdo->query(
            'SELECT id, trust_mark_id FROM oidanchor_trust_mark_types ORDER BY trust_mark_id',
        )->fetchAll(PDO::FETCH_ASSOC);

        $out = [];
        foreach ($types as $type) {
            $issuers = array_map(
                static fn(array $issuer): string => (string) $issuer['issuer'],
                $this->issuersOfType((int) $type['id']),
            );
            $out[(string) $type['trust_mark_id']] = $issuers;
        }

        return $out;
    }


    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function toApi(array $row): array
    {
        $out = [
            'id'     => (int) $row['id'],
            'issuer' => (string) $row['issuer'],
        ];

        if (($row['description'] ?? null) !== null) {
            $out['description'] = (string) $row['description'];
        }

        return $out;
    }
}
