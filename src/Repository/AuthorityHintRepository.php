<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * Authority hints published in the TA's entity configuration (spec: AuthorityHint rows).
 */
class AuthorityHintRepository
{
    private const TABLE = 'oidanchor_authority_hints';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id   TEXT    NOT NULL UNIQUE,
                description TEXT,
                created_at  INTEGER NOT NULL
            )',
        );
    }


    /**
     * @return list<array{id: int, entity_id: string, description: ?string}>
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
     * @return list<string>
     */
    public function entityIds(): array
    {
        $stmt = $this->pdo->query('SELECT entity_id FROM ' . self::TABLE . ' ORDER BY id ASC');

        /** @var list<string> $ids */
        $ids = $stmt->fetchAll(PDO::FETCH_COLUMN);

        return $ids;
    }


    /**
     * @return array{id: int, entity_id: string, description: ?string}|null
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
     * Whether another row (not $exceptId) already claims this entity_id.
     */
    public function findByEntityIdExcept(string $entityId, int $exceptId): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM ' . self::TABLE . ' WHERE entity_id = ? AND id <> ?');
        $stmt->execute([$entityId, $exceptId]);

        return $stmt->fetchColumn() !== false;
    }


    /**
     * @throws InvalidArgumentException When the entity_id is already present.
     */
    public function create(string $entityId, ?string $description): int
    {
        $exists = $this->pdo->prepare('SELECT 1 FROM ' . self::TABLE . ' WHERE entity_id = ?');
        $exists->execute([$entityId]);
        if ($exists->fetchColumn() !== false) {
            throw new InvalidArgumentException(sprintf('Authority hint "%s" already exists.', $entityId));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (entity_id, description, created_at) VALUES (?, ?, ?)',
        );
        $stmt->execute([$entityId, $description, time()]);

        return (int) $this->pdo->lastInsertId();
    }


    public function update(int $id, string $entityId, ?string $description): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET entity_id = ?, description = ? WHERE id = ?',
        );
        $stmt->execute([$entityId, $description, $id]);
    }


    public function delete(int $id): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?');
        $stmt->execute([$id]);
    }


    /**
     * @param array<string,mixed> $row
     * @return array{id: int, entity_id: string, description: ?string}
     */
    private static function toApi(array $row): array
    {
        $out = [
            'id'        => (int) $row['id'],
            'entity_id' => (string) $row['entity_id'],
        ];

        if ($row['description'] !== null) {
            $out['description'] = (string) $row['description'];
        }

        return $out;
    }
}
