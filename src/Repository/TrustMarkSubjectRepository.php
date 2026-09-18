<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * Trust Mark Subjects: the entities an issuance spec issues marks to, each with its own
 * status. This is where revocation / suspension lives in the spec's model — the public
 * /trust_mark_status endpoint consults the subject status before reporting `active`.
 *
 * Migrated from step 7: every distinct (trust_mark_id, sub) in oidanchor_trust_marks_issued
 * gets a subject row (active marks → `active`, revoked marks → `blocked`).
 */
class TrustMarkSubjectRepository
{
    private const TABLE = 'oidanchor_trust_mark_subjects';

    public const STATUSES = ['active', 'blocked', 'pending', 'inactive'];


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . " (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                spec_id           INTEGER NOT NULL,
                entity_id         TEXT    NOT NULL,
                status            TEXT    NOT NULL DEFAULT 'active',
                description       TEXT,
                additional_claims TEXT,
                created_at        INTEGER NOT NULL,
                updated_at        INTEGER,
                UNIQUE (spec_id, entity_id)
            )",
        );

        $this->migrateFromIssuedMarks();
    }


    /**
     * One-shot backfill of subjects from previously issued marks. Idempotent: the
     * INSERT is guarded by the UNIQUE(spec_id, entity_id) constraint.
     */
    private function migrateFromIssuedMarks(): void
    {
        $issuedExists = $this->pdo
            ->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='oidanchor_trust_marks_issued'")
            ->fetchColumn();
        $specsExist = $this->pdo
            ->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='oidanchor_trust_mark_specs'")
            ->fetchColumn();

        if ($issuedExists === false || $specsExist === false) {
            return;
        }

        // A subject is blocked only when it holds no active mark for the type.
        $this->pdo->exec(
            'INSERT OR IGNORE INTO ' . self::TABLE . " (spec_id, entity_id, status, created_at)
             SELECT s.id,
                    i.sub,
                    CASE WHEN SUM(CASE WHEN i.status = 'active' THEN 1 ELSE 0 END) > 0
                         THEN 'active' ELSE 'blocked' END,
                    MIN(i.iat)
             FROM oidanchor_trust_marks_issued i
             JOIN oidanchor_trust_mark_specs s ON s.trust_mark_type = i.trust_mark_id
             GROUP BY s.id, i.sub",
        );
    }


    /**
     * @return list<array<string,mixed>>
     */
    public function findBySpec(int $specId, ?string $status = null): array
    {
        $sql    = 'SELECT * FROM ' . self::TABLE . ' WHERE spec_id = ?';
        $params = [$specId];

        if ($status !== null && $status !== '') {
            $sql     .= ' AND status = ?';
            $params[] = $status;
        }

        $stmt = $this->pdo->prepare($sql . ' ORDER BY id ASC');
        $stmt->execute($params);

        return array_map(
            static fn(array $row): array => self::fromRow($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * @return array<string,mixed>|null
     */
    public function findById(int $specId, int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM ' . self::TABLE . ' WHERE spec_id = ? AND id = ?');
        $stmt->execute([$specId, $id]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::fromRow($row);
    }


    /**
     * Look up a subject by the trust mark type URL — the path the public status endpoint takes.
     *
     * @return array<string,mixed>|null
     */
    public function findByTypeAndEntity(string $trustMarkType, string $entityId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT sub.* FROM ' . self::TABLE . ' sub
             JOIN oidanchor_trust_mark_specs s ON s.id = sub.spec_id
             WHERE s.trust_mark_type = ? AND sub.entity_id = ?',
        );
        $stmt->execute([$trustMarkType, $entityId]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::fromRow($row);
    }


    /**
     * @param array<string,mixed>|null $additionalClaims
     * @throws InvalidArgumentException When the entity is already a subject of the spec.
     */
    public function create(
        int $specId,
        string $entityId,
        string $status,
        ?string $description,
        ?array $additionalClaims,
    ): int {
        $exists = $this->pdo->prepare('SELECT 1 FROM ' . self::TABLE . ' WHERE spec_id = ? AND entity_id = ?');
        $exists->execute([$specId, $entityId]);
        if ($exists->fetchColumn() !== false) {
            throw new InvalidArgumentException(sprintf('Subject "%s" already exists for this spec.', $entityId));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (spec_id, entity_id, status, description, additional_claims, created_at)
             VALUES (?, ?, ?, ?, ?, ?)',
        );
        $stmt->execute([
            $specId,
            $entityId,
            $status,
            $description,
            $additionalClaims !== null ? json_encode($additionalClaims, JSON_UNESCAPED_SLASHES) : null,
            time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    /**
     * @param array<string,mixed> $fields Column => value subset to update.
     */
    public function update(int $id, array $fields): void
    {
        $allowed = ['entity_id', 'status', 'description', 'additional_claims'];

        $sets   = ['updated_at = ?'];
        $values = [time()];

        foreach ($allowed as $col) {
            if (!array_key_exists($col, $fields)) {
                continue;
            }
            $value = $fields[$col];
            if ($col === 'additional_claims' && is_array($value)) {
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


    public function setStatus(int $id, string $status): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET status = ?, updated_at = ? WHERE id = ?',
        );
        $stmt->execute([$status, time(), $id]);
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
        $out = [
            'id'        => (int) $row['id'],
            'spec_id'   => (int) $row['spec_id'],
            'entity_id' => (string) $row['entity_id'],
            'status'    => (string) $row['status'],
        ];

        if (($row['description'] ?? null) !== null) {
            $out['description'] = (string) $row['description'];
        }

        if (($row['additional_claims'] ?? null) !== null) {
            $decoded = json_decode((string) $row['additional_claims'], true);
            if (is_array($decoded)) {
                $out['additional_claims'] = $decoded;
            }
        }

        return $out;
    }
}
