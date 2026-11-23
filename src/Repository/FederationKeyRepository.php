<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Database\KeyMaterialCipher;
use SimpleSAML\Module\oidanchor\Entity\FederationKey;

/**
 * Data-access layer for the TA's federation keys and their lifecycle state
 * (active / expired / revoked, validity window, revocation metadata).
 *
 * Rows are only hard-deleted through the explicit DELETE endpoint; rotation and
 * revocation keep rows so the history remains available (step 10 historical keys).
 *
 * Private key material goes through {@see KeyMaterialCipher}: encrypted at rest when
 * `key_store_secret` is configured, plain JSON otherwise.
 */
class FederationKeyRepository
{
    private const string TABLE = 'oidanchor_federation_keys';


    private readonly KeyMaterialCipher $cipher;


    public function __construct(
        private readonly PDO $pdo,
        ?KeyMaterialCipher $cipher = null,
    ) {
        $this->cipher = $cipher ?? KeyMaterialCipher::disabled();
        $this->ensureSchema();

        if ($this->cipher->isEnabled()) {
            $this->sealPlaintextKeys();
        }
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
     * Encrypt key material stored before a secret was configured (idempotent: sealed rows are skipped).
     */
    private function sealPlaintextKeys(): void
    {
        $rows = $this->pdo->query(
            'SELECT kid, private_jwk FROM ' . self::TABLE . ' WHERE private_jwk IS NOT NULL',
        )->fetchAll(PDO::FETCH_ASSOC);

        $update = $this->pdo->prepare('UPDATE ' . self::TABLE . ' SET private_jwk = ? WHERE kid = ?');
        foreach ($rows as $row) {
            if (!KeyMaterialCipher::isSealed((string) $row['private_jwk'])) {
                $update->execute([
                    $this->cipher->seal((string) $row['private_jwk'], (string) $row['kid']),
                    $row['kid'],
                ]);
            }
        }
    }


    /**
     * @param array<string,mixed> $row
     */
    private function hydrate(array $row): FederationKey
    {
        if (isset($row['private_jwk'])) {
            $row['private_jwk'] = $this->cipher->open((string) $row['private_jwk'], (string) $row['kid']);
        }

        return FederationKey::fromRow($row);
    }


    /**
     * @param array<string,mixed>|null $privateJwk
     */
    private function sealPrivateJwk(?array $privateJwk, string $kid): ?string
    {
        return $privateJwk !== null
            ? $this->cipher->seal((string) json_encode($privateJwk, JSON_UNESCAPED_SLASHES), $kid)
            : null;
    }


    /**
     * All keys, newest first.
     *
     * @return \SimpleSAML\Module\oidanchor\Entity\FederationKey[]
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT * FROM ' . self::TABLE . ' ORDER BY id DESC',
        );

        return array_map(
            fn(array $row): FederationKey => $this->hydrate($row),
            $stmt->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * @phpstan-impure
     */
    public function findByKid(string $kid): ?FederationKey
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM ' . self::TABLE . ' WHERE kid = ?',
        );
        $stmt->execute([$kid]);

        /** @var array<string,mixed>|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $this->hydrate($row);
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

        return $row === false ? null : $this->hydrate($row);
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
            $this->sealPrivateJwk($key->privateJwk, $key->kid),
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


    /**
     * Change a key's algorithm. The JWK material is rewritten in the same statement because
     * web-token refuses to sign with a key whose `alg` member names a different algorithm.
     *
     * @param array<string,mixed>|null $privateJwk
     * @param array<string,mixed> $publicJwk
     */
    public function updateAlg(string $kid, string $alg, ?array $privateJwk, array $publicJwk): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ' . self::TABLE . ' SET alg = ?, private_jwk = ?, public_jwk = ? WHERE kid = ?',
        );
        $stmt->execute([
            $alg,
            $this->sealPrivateJwk($privateJwk, $kid),
            json_encode($publicJwk, JSON_UNESCAPED_SLASHES),
            $kid,
        ]);
    }


    public function hardDelete(string $kid): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE kid = ?',
        );
        $stmt->execute([$kid]);
    }
}
