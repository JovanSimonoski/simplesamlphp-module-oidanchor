<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;

/**
 * Trust marks the TA holds and publishes in its own entity configuration
 * (spec: Entity Configuration Trust Marks). Three variants per the spec:
 * an externally fetched mark (type + issuer), a directly supplied JWT, or a
 * self-issued mark driven by self_issuance_spec.
 */
class EcTrustMarkRepository
{
    private const TABLE = 'oidanchor_ec_trust_marks';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                trust_mark_type      TEXT,
                trust_mark_issuer    TEXT,
                trust_mark           TEXT,
                refresh              INTEGER NOT NULL DEFAULT 0,
                min_lifetime         INTEGER,
                refresh_grace_period INTEGER,
                refresh_rate_limit   INTEGER,
                self_issuance_spec   TEXT,
                last_refresh_at      INTEGER,
                created_at           INTEGER NOT NULL,
                updated_at           INTEGER
            )',
        );
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


    public function typeExists(string $trustMarkType): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM ' . self::TABLE . ' WHERE trust_mark_type = ?',
        );
        $stmt->execute([$trustMarkType]);

        return $stmt->fetchColumn() !== false;
    }


    /**
     * @param array<string,mixed> $data Normalised fields (see fromRow for the shape).
     */
    public function create(array $data): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (trust_mark_type, trust_mark_issuer, trust_mark, refresh, min_lifetime,
                 refresh_grace_period, refresh_rate_limit, self_issuance_spec, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        );
        $stmt->execute([
            $data['trust_mark_type'] ?? null,
            $data['trust_mark_issuer'] ?? null,
            $data['trust_mark'] ?? null,
            !empty($data['refresh']) ? 1 : 0,
            $data['min_lifetime'] ?? null,
            $data['refresh_grace_period'] ?? null,
            $data['refresh_rate_limit'] ?? null,
            isset($data['self_issuance_spec'])
                ? json_encode($data['self_issuance_spec'], JSON_UNESCAPED_SLASHES)
                : null,
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
            'trust_mark_type', 'trust_mark_issuer', 'trust_mark', 'refresh', 'min_lifetime',
            'refresh_grace_period', 'refresh_rate_limit', 'self_issuance_spec', 'last_refresh_at',
        ];

        $sets   = ['updated_at = ?'];
        $values = [time()];

        foreach ($allowed as $col) {
            if (!array_key_exists($col, $fields)) {
                continue;
            }
            $value = $fields[$col];
            if ($col === 'self_issuance_spec' && is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES);
            }
            if ($col === 'refresh') {
                $value = !empty($value) ? 1 : 0;
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
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?');
        $stmt->execute([$id]);
    }


    /**
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function fromRow(array $row): array
    {
        return [
            'id'                   => (int) $row['id'],
            'trust_mark_type'      => $row['trust_mark_type'] !== null ? (string) $row['trust_mark_type'] : null,
            'trust_mark_issuer'    => $row['trust_mark_issuer'] !== null ? (string) $row['trust_mark_issuer'] : null,
            'trust_mark'           => $row['trust_mark'] !== null ? (string) $row['trust_mark'] : null,
            'refresh'              => (bool) $row['refresh'],
            'min_lifetime'         => $row['min_lifetime'] !== null ? (int) $row['min_lifetime'] : null,
            'refresh_grace_period' => $row['refresh_grace_period'] !== null ? (int) $row['refresh_grace_period'] : null,
            'refresh_rate_limit'   => $row['refresh_rate_limit'] !== null ? (int) $row['refresh_rate_limit'] : null,
            'self_issuance_spec'   => $row['self_issuance_spec'] !== null
                ? json_decode((string) $row['self_issuance_spec'], true)
                : null,
            'last_refresh_at'      => $row['last_refresh_at'] !== null ? (int) $row['last_refresh_at'] : null,
        ];
    }
}
