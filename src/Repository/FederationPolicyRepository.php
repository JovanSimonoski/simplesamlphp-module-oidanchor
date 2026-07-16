<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use PDOException;
use SimpleSAML\Module\oidanchor\Entity\FederationPolicy;

class FederationPolicyRepository
{
    private const TABLE = 'oidanchor_metadata_policies';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                entity_type TEXT    NOT NULL PRIMARY KEY,
                policy      TEXT    NOT NULL,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            )',
        );
    }


    /**
     * @return FederationPolicy[]
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT * FROM ' . self::TABLE . ' ORDER BY entity_type ASC',
        );

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(
            static fn(array $row): FederationPolicy => FederationPolicy::fromRow($row),
            $rows,
        );
    }


    public function findByEntityType(string $entityType): ?FederationPolicy
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE entity_type = ?',
        );
        $stmt->execute([$entityType]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : FederationPolicy::fromRow($row);
    }


    public function upsert(string $entityType, array $policy): void
    {
        $now        = time();
        $policyJson = json_encode($policy, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (entity_type, policy, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(entity_type) DO UPDATE SET policy = excluded.policy, updated_at = excluded.updated_at',
        );
        $stmt->execute([$entityType, $policyJson, $now, $now]);
    }


    public function delete(string $entityType): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE entity_type = ?',
        );
        $stmt->execute([$entityType]);
    }
}
