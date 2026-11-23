<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Database\Upsert;

/**
 * What the last collection refresh learned about each active subordinate by resolving its trust
 * chain: the entity types it declares, its informational metadata per type, and the Trust Marks
 * that verified. Served by the Entity Collection endpoint; written only by the refresh (cron).
 */
class EntityCollectionRepository
{
    private const string TABLE = 'oidanchor_entity_collection';

    private const int JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;


    public function __construct(private readonly PDO $pdo)
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                entity_id    TEXT    NOT NULL PRIMARY KEY,
                entity_types TEXT    NOT NULL,
                entity_infos TEXT    NOT NULL,
                trust_marks  TEXT    NOT NULL,
                error        TEXT,
                refreshed_at INTEGER NOT NULL
            )',
        );
    }


    /**
     * @param list<string> $entityTypes
     * @param array<string,array<string,mixed>> $entityInfos Keyed by entity type.
     * @param list<array{trust_mark_type:string,trust_mark:string}> $trustMarks
     * @param string|null $error Why the last refresh could not resolve the entity.
     */
    public function save(
        string $entityId,
        array $entityTypes,
        array $entityInfos,
        array $trustMarks,
        ?string $error,
        int $refreshedAt,
    ): void {
        Upsert::run($this->pdo, self::TABLE, ['entity_id' => $entityId], [
            'entity_types' => json_encode($entityTypes, self::JSON_FLAGS),
            'entity_infos' => json_encode((object) $entityInfos, self::JSON_FLAGS),
            'trust_marks'  => json_encode($trustMarks, self::JSON_FLAGS),
            'error'        => $error,
            'refreshed_at' => $refreshedAt,
        ]);
    }


    /**
     * @return array<string,array{
     *     entity_types: list<string>,
     *     entity_infos: array<string,array<string,mixed>>,
     *     trust_marks: list<array{trust_mark_type:string,trust_mark:string}>,
     *     error: ?string,
     *     refreshed_at: int,
     * }> Keyed by entity_id.
     */
    public function all(): array
    {
        $rows = $this->pdo->query('SELECT * FROM ' . self::TABLE)->fetchAll(PDO::FETCH_ASSOC);

        $entries = [];
        foreach ($rows as $row) {
            $entries[(string) $row['entity_id']] = [
                'entity_types' => self::decodeList($row['entity_types']),
                'entity_infos' => (array) json_decode((string) $row['entity_infos'], true),
                'trust_marks'  => self::decodeList($row['trust_marks']),
                'error'        => isset($row['error']) ? (string) $row['error'] : null,
                'refreshed_at' => (int) $row['refreshed_at'],
            ];
        }

        return $entries;
    }


    /**
     * Forget every entity not in the list (no longer an active subordinate).
     *
     * @param list<string> $entityIds
     */
    public function retainOnly(array $entityIds): void
    {
        if ($entityIds === []) {
            $this->pdo->exec('DELETE FROM ' . self::TABLE);

            return;
        }

        $placeholders = implode(', ', array_fill(0, count($entityIds), '?'));
        $this->pdo
            ->prepare('DELETE FROM ' . self::TABLE . ' WHERE entity_id NOT IN (' . $placeholders . ')')
            ->execute($entityIds);
    }


    /**
     * @return list<mixed>
     */
    private static function decodeList(mixed $json): array
    {
        $decoded = json_decode((string) $json, true);

        return is_array($decoded) ? array_values($decoded) : [];
    }
}
