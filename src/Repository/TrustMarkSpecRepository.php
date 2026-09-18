<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * Trust Mark Issuance Specs: templates governing how the TA issues marks of a type
 * (lifetime, ref, logo, delegation JWT, general additional claims, eligibility, caching).
 *
 * Migrated from the step-7 model: each existing `oidanchor_trust_mark_types` row's
 * logo_uri / ref_uri / default_lifetime / extra_claims becomes a spec row, so previously
 * catalogued types keep issuing marks with the same descriptive claims.
 */
class TrustMarkSpecRepository
{
    private const TABLE = 'oidanchor_trust_mark_specs';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                trust_mark_type   TEXT    NOT NULL UNIQUE,
                description       TEXT,
                lifetime          INTEGER,
                ref               TEXT,
                logo_uri          TEXT,
                delegation_jwt    TEXT,
                additional_claims TEXT,
                eligibility_config TEXT,
                cache_ttl         INTEGER NOT NULL DEFAULT 0,
                created_at        INTEGER NOT NULL,
                updated_at        INTEGER
            )',
        );

        $this->migrateFromTypeCatalog();
    }


    /**
     * One-shot backfill: create a spec for every catalogued type that has none yet, carrying
     * over the step-7 per-type issuance fields. Idempotent (only inserts missing rows).
     */
    private function migrateFromTypeCatalog(): void
    {
        $tableExists = $this->pdo
            ->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='oidanchor_trust_mark_types'")
            ->fetchColumn();

        if ($tableExists === false) {
            return;
        }

        $rows = $this->pdo->query(
            'SELECT t.trust_mark_id, t.description, t.logo_uri, t.ref_uri, t.default_lifetime, t.extra_claims
             FROM oidanchor_trust_mark_types t
             LEFT JOIN ' . self::TABLE . ' s ON s.trust_mark_type = t.trust_mark_id
             WHERE s.id IS NULL',
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $stmt = $this->pdo->prepare(
                'INSERT INTO ' . self::TABLE . '
                    (trust_mark_type, description, lifetime, ref, logo_uri, additional_claims, cache_ttl, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
            );
            $stmt->execute([
                $row['trust_mark_id'],
                $row['description'],
                $row['default_lifetime'],
                $row['ref_uri'],
                $row['logo_uri'],
                $row['extra_claims'],
                time(),
            ]);
        }
    }


    /**
     * @return list<array<string,mixed>>
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query('SELECT * FROM ' . self::TABLE . ' ORDER BY id ASC');

        return array_map(
            static fn(array $row): array => self::fromRow($row),
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

        return $row === false ? null : self::fromRow($row);
    }


    /**
     * @return array<string,mixed>|null
     */
    public function findByType(string $trustMarkType): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM ' . self::TABLE . ' WHERE trust_mark_type = ?');
        $stmt->execute([$trustMarkType]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::fromRow($row);
    }


    /**
     * @param array<string,mixed> $data
     * @throws InvalidArgumentException When a spec for the type already exists.
     */
    public function create(array $data): int
    {
        $type = (string) $data['trust_mark_type'];
        if ($this->findByType($type) !== null) {
            throw new InvalidArgumentException(sprintf('An issuance spec for "%s" already exists.', $type));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (trust_mark_type, description, lifetime, ref, logo_uri, delegation_jwt,
                 additional_claims, eligibility_config, cache_ttl, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        );
        $stmt->execute([
            $type,
            $data['description'] ?? null,
            $data['lifetime'] ?? null,
            $data['ref'] ?? null,
            $data['logo_uri'] ?? null,
            $data['delegation_jwt'] ?? null,
            isset($data['additional_claims']) ? json_encode($data['additional_claims'], JSON_UNESCAPED_SLASHES) : null,
            isset($data['eligibility_config']) ? json_encode($data['eligibility_config'], JSON_UNESCAPED_SLASHES) : null,
            (int) ($data['cache_ttl'] ?? 0),
            time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    /**
     * @param array<string,mixed> $fields Column => value subset to update.
     */
    public function update(int $id, array $fields): void
    {
        $allowed = [
            'trust_mark_type', 'description', 'lifetime', 'ref', 'logo_uri',
            'delegation_jwt', 'additional_claims', 'eligibility_config', 'cache_ttl',
        ];

        $sets   = ['updated_at = ?'];
        $values = [time()];

        foreach ($allowed as $col) {
            if (!array_key_exists($col, $fields)) {
                continue;
            }
            $value = $fields[$col];
            if (in_array($col, ['additional_claims', 'eligibility_config'], true) && is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES);
            }
            $sets[]   = "$col = ?";
            $values[] = $value;
        }

        $values[] = $id;
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET ' . implode(', ', $sets) . ' WHERE id = ?',
        );
        $stmt->execute($values);
    }


    public function delete(int $id): void
    {
        $this->pdo->prepare('DELETE FROM oidanchor_trust_mark_subjects WHERE spec_id = ?')->execute([$id]);
        $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?')->execute([$id]);
    }


    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function fromRow(array $row): array
    {
        $out = [
            'id'              => (int) $row['id'],
            'trust_mark_type' => (string) $row['trust_mark_type'],
            'cache_ttl'       => (int) $row['cache_ttl'],
        ];

        foreach (['description', 'ref', 'logo_uri', 'delegation_jwt'] as $field) {
            if (($row[$field] ?? null) !== null) {
                $out[$field] = (string) $row[$field];
            }
        }

        if (($row['lifetime'] ?? null) !== null) {
            $out['lifetime'] = (int) $row['lifetime'];
        }

        foreach (['additional_claims', 'eligibility_config'] as $field) {
            if (($row[$field] ?? null) !== null) {
                $decoded = json_decode((string) $row[$field], true);
                if (is_array($decoded)) {
                    $out[$field] = $decoded;
                }
            }
        }

        return $out;
    }
}
