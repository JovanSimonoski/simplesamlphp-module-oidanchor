<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use InvalidArgumentException;
use PDO;

/**
 * AdditionalClaim rows ({ id, claim, value, crit }) for the three scopes the spec manages:
 * the TA's own entity configuration, the general defaults applied to every subordinate
 * statement, and per-subordinate claims. One table serves all three.
 */
class AdditionalClaimsRepository
{
    private const TABLE = 'oidanchor_additional_claims';

    public const SCOPE_ENTITY_CONFIGURATION = 'entity_configuration';
    public const SCOPE_SUBORDINATE_GENERAL  = 'subordinate_general';
    public const SCOPE_SUBORDINATE          = 'subordinate';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        // subordinate_id is NOT NULL DEFAULT 0 (0 = "no subordinate", used by the entity-configuration
        // and general scopes). Storing 0 rather than NULL keeps the UNIQUE index a plain column tuple
        // and lets `subordinate_id = ?` use the column's INTEGER affinity — a COALESCE() expression
        // would strip that affinity, and PDO binds execute() params as strings under native prepares,
        // so `COALESCE(subordinate_id, 0) = '0'` never matches integer 0.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scope          TEXT    NOT NULL,
                subordinate_id INTEGER NOT NULL DEFAULT 0,
                claim          TEXT    NOT NULL,
                value          TEXT    NOT NULL,
                crit           INTEGER NOT NULL DEFAULT 0,
                created_at     INTEGER NOT NULL,
                updated_at     INTEGER
            )',
        );

        $this->pdo->exec(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_additional_claims_unique
                ON ' . self::TABLE . ' (scope, subordinate_id, claim)',
        );
    }


    /**
     * All claim rows for a scope, insertion order.
     *
     * @return list<array{id: int, claim: string, value: mixed, crit: bool}>
     */
    public function findAll(string $scope, ?int $subordinateId = null): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . '
             WHERE scope = ? AND subordinate_id = ?
             ORDER BY id ASC',
        );
        $stmt->execute([$scope, $subordinateId ?? 0]);

        return array_map(
            static fn(array $row): array => self::rowToClaim($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * The scope's claims as the spec's AdditionalClaims map ({ claim: value }).
     *
     * @return array<string,mixed>
     */
    public function asMap(string $scope, ?int $subordinateId = null): array
    {
        $map = [];
        foreach ($this->findAll($scope, $subordinateId) as $row) {
            $map[$row['claim']] = $row['value'];
        }

        return $map;
    }


    /**
     * @return array{id: int, claim: string, value: mixed, crit: bool}|null
     */
    public function findById(string $scope, int $id, ?int $subordinateId = null): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . '
             WHERE id = ? AND scope = ? AND subordinate_id = ?',
        );
        $stmt->execute([$id, $scope, $subordinateId ?? 0]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::rowToClaim($row);
    }


    public function claimExists(string $scope, string $claim, ?int $subordinateId = null): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1 FROM ' . self::TABLE . '
             WHERE scope = ? AND subordinate_id = ? AND claim = ?',
        );
        $stmt->execute([$scope, $subordinateId ?? 0, $claim]);

        return $stmt->fetchColumn() !== false;
    }


    /**
     * Insert a claim row; returns the new row id.
     *
     * @throws InvalidArgumentException When the claim name already exists in the scope.
     */
    public function create(string $scope, string $claim, mixed $value, bool $crit, ?int $subordinateId = null): int
    {
        if ($this->claimExists($scope, $claim, $subordinateId)) {
            throw new InvalidArgumentException(sprintf('Claim "%s" already exists.', $claim));
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (scope, subordinate_id, claim, value, crit, created_at)
             VALUES (?, ?, ?, ?, ?, ?)',
        );
        $stmt->execute([
            $scope,
            $subordinateId ?? 0,
            $claim,
            json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $crit ? 1 : 0,
            time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    public function update(int $id, string $claim, mixed $value, bool $crit): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . '
             SET claim = ?, value = ?, crit = ?, updated_at = ?
             WHERE id = ?',
        );
        $stmt->execute([
            $claim,
            json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $crit ? 1 : 0,
            time(),
            $id,
        ]);
    }


    public function delete(int $id): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE id = ?');
        $stmt->execute([$id]);
    }


    /**
     * Replace every claim row in a scope with the given (claim, value, crit) tuples.
     *
     * @param list<array{claim: string, value: mixed, crit: bool}> $claims
     */
    public function replaceAll(string $scope, array $claims, ?int $subordinateId = null): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE scope = ? AND subordinate_id = ?',
        );
        $stmt->execute([$scope, $subordinateId ?? 0]);

        foreach ($claims as $claim) {
            $this->create($scope, $claim['claim'], $claim['value'], $claim['crit'], $subordinateId);
        }
    }


    public function deleteForSubordinate(int $subordinateId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE scope = ? AND subordinate_id = ?',
        );
        $stmt->execute([self::SCOPE_SUBORDINATE, $subordinateId]);
    }


    /**
     * @param array<string,mixed> $row
     * @return array{id: int, claim: string, value: mixed, crit: bool}
     */
    private static function rowToClaim(array $row): array
    {
        return [
            'id'    => (int) $row['id'],
            'claim' => (string) $row['claim'],
            'value' => json_decode((string) $row['value'], true),
            'crit'  => (bool) $row['crit'],
        ];
    }
}
