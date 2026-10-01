<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;

/**
 * Audit trail for subordinate mutations (spec: GET /subordinates/{id}/history).
 *
 * Every mutating subordinate operation (API and admin UI) records an event. Events are
 * keyed by both the surrogate subordinate id and the entity_id so history survives deletes.
 */
class SubordinateEventRepository
{
    private const TABLE = 'oidanchor_subordinate_events';

    /** Spec SubordinateEvent.type vocabulary. */
    public const TYPES = [
        'created', 'deleted', 'status_updated', 'updated',
        'jwk_added', 'jwk_removed', 'jwks_replaced',
        'metadata_updated', 'metadata_deleted',
        'policy_updated', 'policy_deleted',
        'constraints_updated', 'constraints_deleted',
        'claims_updated', 'claim_deleted',
    ];


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                subordinate_id INTEGER,
                entity_id      TEXT    NOT NULL,
                timestamp      INTEGER NOT NULL,
                type           TEXT    NOT NULL,
                status         TEXT,
                message        TEXT,
                actor          TEXT
            )',
        );

        $this->pdo->exec(
            'CREATE INDEX IF NOT EXISTS idx_sub_events_lookup
                ON ' . self::TABLE . ' (subordinate_id, timestamp)',
        );
    }


    public function record(
        ?int $subordinateId,
        string $entityId,
        string $type,
        ?string $status = null,
        ?string $message = null,
        ?string $actor = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (subordinate_id, entity_id, timestamp, type, status, message, actor)
             VALUES (?, ?, ?, ?, ?, ?, ?)',
        );
        $stmt->execute([$subordinateId, $entityId, time(), $type, $status, $message, $actor]);
    }


    /**
     * Query events for one subordinate, newest first, with pagination and filters.
     *
     * @return array{events: list<array<string,mixed>>, total: int}
     */
    public function query(
        int $subordinateId,
        int $limit,
        int $offset,
        ?string $type = null,
        ?int $from = null,
        ?int $to = null,
    ): array {
        $where  = ['subordinate_id = ?'];
        $params = [$subordinateId];

        if ($type !== null && $type !== '') {
            $where[]  = 'type = ?';
            $params[] = $type;
        }
        if ($from !== null) {
            $where[]  = 'timestamp >= ?';
            $params[] = $from;
        }
        if ($to !== null) {
            $where[]  = 'timestamp <= ?';
            $params[] = $to;
        }

        $whereSql = implode(' AND ', $where);

        $countStmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM ' . self::TABLE . ' WHERE ' . $whereSql,
        );
        $countStmt->execute($params);
        $total = (int) $countStmt->fetchColumn();

        $stmt = $this->pdo->prepare(
            'SELECT timestamp, type, status, message, actor
             FROM ' . self::TABLE . '
             WHERE ' . $whereSql . '
             ORDER BY timestamp DESC, id DESC
             LIMIT ? OFFSET ?',
        );
        $stmt->execute([...$params, $limit, $offset]);

        $events = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $events[] = [
                'timestamp' => (int) $row['timestamp'],
                'type'      => (string) $row['type'],
                'status'    => $row['status'] !== null ? (string) $row['status'] : null,
                'message'   => $row['message'] !== null ? (string) $row['message'] : null,
                'actor'     => $row['actor'] !== null ? (string) $row['actor'] : null,
            ];
        }

        return ['events' => $events, 'total' => $total];
    }
}
