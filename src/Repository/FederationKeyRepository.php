<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Entity\FederationKey;

/**
 * Data-access layer for the TA's federation keys and their lifecycle state
 * (active / expired / revoked, validity window, revocation metadata).
 *
 * Rows are only hard-deleted through the explicit DELETE endpoint; rotation and
 * revocation keep rows so the history remains available (step 10 historical keys).
 */
class FederationKeyRepository
{
    private const TABLE = 'oidanchor_federation_keys';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . " (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                kid               TEXT    NOT NULL UNIQUE,
                private_jwk       TEXT,
                public_jwk        TEXT    NOT NULL,
                alg               TEXT,
                kms_managed       INTEGER NOT NULL DEFAULT 0,
                status            TEXT    NOT NULL DEFAULT 'active',
                iat               INTEGER,
                nbf               INTEGER,
                exp               INTEGER,
                revoked_at        INTEGER,
                revocation_reason TEXT,
                created_at        INTEGER NOT NULL
            )",
        );
    }


    /**
     * All keys, newest first.
     *
     * @return FederationKey[]
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT * FROM ' . self::TABLE . ' ORDER BY id DESC',
        );

        return array_map(
            static fn(array $row): FederationKey => FederationKey::fromRow($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    public function findByKid(string $kid): ?FederationKey
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE kid = ?',
        );
        $stmt->execute([$kid]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : FederationKey::fromRow($row);
    }


    /**
     * The newest active KMS-managed key — the TA's current signing key.
     */
    public function findActiveSigningKey(): ?FederationKey
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . "
             WHERE kms_managed = 1 AND status = 'active'
             ORDER BY id DESC LIMIT 1",
        );
        $stmt->execute();

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : FederationKey::fromRow($row);
    }


    public function create(FederationKey $key): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . '
                (kid, private_jwk, public_jwk, alg, kms_managed, status, iat, nbf, exp,
                 revoked_at, revocation_reason, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        );

        $stmt->execute([
            $key->kid,
            $key->privateJwk !== null ? json_encode($key->privateJwk, JSON_UNESCAPED_SLASHES) : null,
            json_encode($key->publicJwk, JSON_UNESCAPED_SLASHES),
            $key->alg,
            $key->kmsManaged ? 1 : 0,
            $key->status,
            $key->iat,
            $key->nbf,
            $key->exp,
            $key->revokedAt,
            $key->revocationReason,
            $key->createdAt,
        ]);

        return (int) $this->pdo->lastInsertId();
    }


    /**
     * Update the editable validity metadata (nbf / exp) of a key.
     */
    public function updateValidity(string $kid, ?int $nbf, ?int $exp, bool $setNbf, bool $setExp): void
    {
        $sets   = [];
        $values = [];

        if ($setNbf) {
            $sets[]   = 'nbf = ?';
            $values[] = $nbf;
        }
        if ($setExp) {
            $sets[]   = 'exp = ?';
            $values[] = $exp;
        }

        if ($sets === []) {
            return;
        }

        $values[] = $kid;
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET ' . implode(', ', $sets) . ' WHERE kid = ?',
        );
        $stmt->execute($values);
    }


    /**
     * Mark a key expired (rotation): status flips and exp is set to the takeover time
     * (or the end of the overlap window).
     */
    public function markExpired(string $kid, int $exp): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . " SET status = 'expired', exp = ? WHERE kid = ?",
        );
        $stmt->execute([$exp, $kid]);
    }


    public function revoke(string $kid, ?string $reason): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . "
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
             WHERE kid = ?",
        );
        $stmt->execute([time(), $reason, $kid]);
    }


    public function updateAlg(string $kid, string $alg): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET alg = ? WHERE kid = ?',
        );
        $stmt->execute([$alg, $kid]);
    }


    public function hardDelete(string $kid): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE kid = ?',
        );
        $stmt->execute([$kid]);
    }
}
