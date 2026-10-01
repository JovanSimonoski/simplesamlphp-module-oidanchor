<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use PDOException;
use SimpleSAML\Module\oidanchor\Entity\IssuedTrustMark;

/**
 * Data-access layer for every Trust Mark the TA has issued.
 *
 * Rows are never updated except to flip status on revocation, so the table doubles as an
 * audit log. Re-issuance inserts a new row, leaving prior (revoked) rows intact for history.
 */
class IssuedTrustMarkRepository
{
    private const TABLE = 'oidanchor_trust_marks_issued';


    public function __construct(private readonly PDO $pdo)
    {
        TrustMarkTypeColumnMigration::run($pdo);
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                trust_mark_type   TEXT    NOT NULL,
                sub               TEXT    NOT NULL,
                jwt               TEXT    NOT NULL,
                iat               INTEGER NOT NULL,
                exp               INTEGER,
                status            TEXT    NOT NULL DEFAULT \'active\',
                revoked_at        INTEGER,
                revocation_reason TEXT
            )',
        );

        try {
            $this->pdo->exec(
                'CREATE INDEX IF NOT EXISTS idx_tm_issued_lookup
                    ON ' . self::TABLE . ' (trust_mark_type, sub, status)',
            );
        } catch (PDOException) {
            // Index already exists — safe to ignore.
        }
    }


    /**
     * Return issued marks, optionally filtered by type, subject and/or status, newest first.
     *
     * @return IssuedTrustMark[]
     */
    public function findAll(?string $trustMarkType = null, ?string $sub = null, ?string $status = null): array
    {
        $where  = [];
        $params = [];

        if ($trustMarkType !== null && $trustMarkType !== '') {
            $where[]  = 'trust_mark_type = ?';
            $params[] = $trustMarkType;
        }

        if ($sub !== null && $sub !== '') {
            $where[]  = 'sub = ?';
            $params[] = $sub;
        }

        if ($status !== null && $status !== '') {
            $where[]  = 'status = ?';
            $params[] = $status;
        }

        $sql = 'SELECT * FROM ' . self::TABLE;
        if ($where !== []) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= ' ORDER BY id DESC';

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        return array_map(
            static fn(array $row): IssuedTrustMark => IssuedTrustMark::fromRow($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    public function findById(int $id): ?IssuedTrustMark
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE id = ?',
        );
        $stmt->execute([$id]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : IssuedTrustMark::fromRow($row);
    }


    /**
     * Most recent issued row for a (type, sub) pair regardless of status.
     * Used by the status endpoint, which must be able to report 'revoked' / 'expired'.
     */
    public function findLatest(string $trustMarkType, string $sub): ?IssuedTrustMark
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . '
             WHERE trust_mark_type = ? AND sub = ?
             ORDER BY id DESC LIMIT 1',
        );
        $stmt->execute([$trustMarkType, $sub]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : IssuedTrustMark::fromRow($row);
    }


    /**
     * Most recent active row for a (type, sub) pair.
     */
    public function findActive(string $trustMarkType, string $sub): ?IssuedTrustMark
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . "
             WHERE trust_mark_type = ? AND sub = ? AND status = 'active'
             ORDER BY id DESC LIMIT 1",
        );
        $stmt->execute([$trustMarkType, $sub]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : IssuedTrustMark::fromRow($row);
    }


    /**
     * All active, unexpired marks held by a subject — used to embed in subordinate statements.
     *
     * @return IssuedTrustMark[]
     */
    public function findActiveBySub(string $sub): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . "
             WHERE sub = ? AND status = 'active' AND (exp IS NULL OR exp > ?)
             ORDER BY iat ASC",
        );
        $stmt->execute([$sub, time()]);

        return array_map(
            static fn(array $row): IssuedTrustMark => IssuedTrustMark::fromRow($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * Insert a new issued-mark row and return its auto-increment id.
     */
    public function create(IssuedTrustMark $mark): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (trust_mark_type, sub, jwt, iat, exp, status, revoked_at, revocation_reason)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        );

        $stmt->execute([
            $mark->trustMarkType,
            $mark->sub,
            $mark->jwt,
            $mark->iat,
            $mark->exp,
            $mark->status,
            $mark->revokedAt,
            $mark->revocationReason,
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    public function revoke(int $id, ?string $reason = null): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . "
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
             WHERE id = ?",
        );
        $stmt->execute([time(), $reason, $id]);
    }


    /**
     * Count active issued marks referencing a given type (used to warn before type deletion).
     */
    public function countActiveByType(string $trustMarkType): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM ' . self::TABLE . " WHERE trust_mark_type = ? AND status = 'active'",
        );
        $stmt->execute([$trustMarkType]);

        return (int) $stmt->fetchColumn();
    }
}
