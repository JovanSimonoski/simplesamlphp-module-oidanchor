<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;

/**
 * Stored metadata for the TA's own entity configuration, one JSON document per entity type.
 * The entity-configuration builder overlays these documents on the auto-derived
 * federation_entity endpoint claims, so API edits are immediately published.
 */
class EcMetadataRepository
{
    private const TABLE = 'oidanchor_ec_metadata';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                entity_type TEXT    NOT NULL PRIMARY KEY,
                metadata    TEXT    NOT NULL,
                updated_at  INTEGER NOT NULL
            )',
        );
    }


    /**
     * Whole stored metadata document: { entityType: { claim: value } }.
     *
     * @return array<string,array<string,mixed>>
     */
    public function all(): array
    {
        $stmt = $this->pdo->query('SELECT entity_type, metadata FROM ' . self::TABLE . ' ORDER BY entity_type');

        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $decoded = json_decode((string) $row['metadata'], true);
            $out[(string) $row['entity_type']] = is_array($decoded) ? $decoded : [];
        }

        return $out;
    }


    /**
     * @return array<string,mixed>|null
     */
    public function forType(string $entityType): ?array
    {
        $stmt = $this->pdo->prepare('SELECT metadata FROM ' . self::TABLE . ' WHERE entity_type = ?');
        $stmt->execute([$entityType]);

        $value = $stmt->fetchColumn();
        if ($value === false) {
            return null;
        }

        $decoded = json_decode((string) $value, true);

        return is_array($decoded) ? $decoded : [];
    }


    /**
     * @param array<string,mixed> $metadata
     */
    public function upsert(string $entityType, array $metadata): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (entity_type, metadata, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(entity_type) DO UPDATE SET
                 metadata   = excluded.metadata,
                 updated_at = excluded.updated_at',
        );
        $stmt->execute([
            $entityType,
            json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            time(),
        ]);
    }


    /**
     * Replace the whole document (delete types not present, upsert the rest).
     *
     * @param array<string,array<string,mixed>> $document
     */
    public function replaceAll(array $document): void
    {
        foreach (array_keys($this->all()) as $entityType) {
            if (!array_key_exists($entityType, $document)) {
                $this->delete($entityType);
            }
        }

        foreach ($document as $entityType => $metadata) {
            $this->upsert((string) $entityType, is_array($metadata) ? $metadata : []);
        }
    }


    public function delete(string $entityType): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE entity_type = ?');
        $stmt->execute([$entityType]);
    }
}
