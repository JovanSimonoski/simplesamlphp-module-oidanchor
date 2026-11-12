<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Database\Upsert;
use SimpleSAML\Module\oidanchor\Entity\FederationPolicy;

class FederationPolicyRepository
{
    private const string TABLE = 'oidanchor_metadata_policies';


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
     * @return \SimpleSAML\Module\oidanchor\Entity\FederationPolicy[]
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
        $now = time();

        Upsert::run(
            $this->pdo,
            self::TABLE,
            ['entity_type' => $entityType],
            ['policy' => json_encode($policy, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'updated_at' => $now],
            ['created_at' => $now],
        );
    }


    public function delete(string $entityType): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE entity_type = ?',
        );
        $stmt->execute([$entityType]);
    }
}
