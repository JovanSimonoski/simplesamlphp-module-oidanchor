<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

/**
 * A federation key managed by the TA, with its lifecycle state.
 *
 * kmsManaged keys carry private material and are used for signing (the newest active one
 * is the signing key); API-managed entries (kmsManaged = false) are public-only keys that
 * an admin publishes alongside, e.g. externally-held keys.
 */
class FederationKey
{
    /**
     * @param array<string,mixed>|null $privateJwk
     * @param array<string,mixed> $publicJwk
     */
    public function __construct(
        public readonly ?int $id,
        public readonly string $kid,
        public readonly ?array $privateJwk,
        public readonly array $publicJwk,
        public readonly ?string $alg,
        public readonly bool $kmsManaged,
        public readonly string $status,
        public readonly ?int $iat,
        public readonly ?int $nbf,
        public readonly ?int $exp,
        public readonly ?int $revokedAt,
        public readonly ?string $revocationReason,
        public readonly int $createdAt,
    ) {
    }


    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            id:               (int) $row['id'],
            kid:              (string) $row['kid'],
            privateJwk:       isset($row['private_jwk']) ? json_decode((string) $row['private_jwk'], true) : null,
            publicJwk:        (array) json_decode((string) $row['public_jwk'], true),
            alg:              isset($row['alg']) ? (string) $row['alg'] : null,
            kmsManaged:       (bool) $row['kms_managed'],
            status:           (string) $row['status'],
            iat:              isset($row['iat']) ? (int) $row['iat'] : null,
            nbf:              isset($row['nbf']) ? (int) $row['nbf'] : null,
            exp:              isset($row['exp']) ? (int) $row['exp'] : null,
            revokedAt:        isset($row['revoked_at']) ? (int) $row['revoked_at'] : null,
            revocationReason: isset($row['revocation_reason']) ? (string) $row['revocation_reason'] : null,
            createdAt:        (int) $row['created_at'],
        );
    }


    /**
     * The spec's PublicKeyEntry shape ({ kid, key, iat?, nbf?, exp?, revoked_at?, reason? }).
     *
     * @return array<string,mixed>
     */
    public function toPublicKeyEntry(): array
    {
        $entry = [
            'kid' => $this->kid,
            'key' => $this->publicJwk,
        ];

        foreach (['iat' => $this->iat, 'nbf' => $this->nbf, 'exp' => $this->exp, 'revoked_at' => $this->revokedAt] as $claim => $value) {
            if ($value !== null) {
                $entry[$claim] = $value;
            }
        }

        if ($this->revocationReason !== null) {
            $entry['reason'] = $this->revocationReason;
        }

        return $entry;
    }


    /**
     * Whether the key belongs in the published JWKS: never revoked, and within its validity
     * window. Expired-but-not-yet-past-exp keys stay published (rotation overlap).
     */
    public function isPublishable(int $now): bool
    {
        if ($this->status === 'revoked') {
            return false;
        }

        if ($this->exp !== null && $this->exp <= $now) {
            return false;
        }

        return !($this->nbf !== null && $this->nbf > $now);
    }
}
