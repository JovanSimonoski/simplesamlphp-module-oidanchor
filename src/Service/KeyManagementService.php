<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PDO;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\FederationKey;
use SimpleSAML\Module\oidanchor\Repository\FederationKeyRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwk\JwkDecorator;

/**
 * The module's "KMS": manages the TA's federation keys in the database with full lifecycle
 * state (active / expired / revoked), rotation (manual + interval-based), signing-algorithm
 * switching and RSA key-length configuration.
 *
 * On first use the config-file signing key is imported as the initial active KMS-managed key,
 * so existing deployments keep signing with the same key until an admin rotates.
 *
 * All JWK material handling goes through simplesamlphp/openid (JwkDecoratorFactory / JwkDecorator).
 * Key generation is the one exception: the openid library only loads existing keys (checked
 * Jwk\Factories\JwkDecoratorFactory — it exposes fromData, fromPkcs1Or8Key(File),
 * fromPkcs12CertificateFile and fromX509Certificate(File) only, no generator), so we call
 * Jose\Component\KeyManagement\JWKFactory (the exact web-token class the library itself wraps)
 * and re-wrap the result via JwkDecoratorFactory::fromData.
 */
class KeyManagementService
{
    private const DEFAULT_RSA_KEY_LEN = 2048;

    /** Default overlap (seconds) during which a rotated-out key stays published. */
    private const DEFAULT_ROTATION_OVERLAP = 0;

    private ?SettingsRepository $settings = null;

    private ?FederationKeyRepository $keys = null;


    public function __construct(
        private readonly Configuration $moduleConfig,
        private readonly PDO $pdo,
    ) {
    }


    // -------------------------------------------------------------------------
    // Signing context (used by FederationKeyService)
    // -------------------------------------------------------------------------

    /**
     * The current signing key context. Bootstraps the store from the config file key and
     * applies interval-based rotation when due.
     *
     * @return array{
     *     signingKey: JwkDecorator,
     *     kid: string,
     *     publicJwkData: array<string,mixed>,
     *     algorithm: SignatureAlgorithmEnum
     * }
     */
    public function activeSigningContext(): array
    {
        $key = $this->ensureActiveSigningKey();
        $key = $this->maybeAutoRotate($key);

        if ($key->privateJwk === null) {
            throw new RuntimeException('oidanchor: active signing key has no private material.');
        }

        $signingKey = (new Jwk())->jwkDecoratorFactory()->fromData($key->privateJwk);

        return [
            'signingKey'    => $signingKey,
            'kid'           => $key->kid,
            'publicJwkData' => $key->publicJwk,
            'algorithm'     => SignatureAlgorithmEnum::from($key->alg ?? $this->configuredAlgorithm()),
        ];
    }


    /**
     * The published federation JWKS: every non-revoked key inside its validity window
     * (rotated-out keys stay until their exp passes — the rotation overlap).
     *
     * @return array{keys: list<array<string,mixed>>}
     */
    public function publicJwks(): array
    {
        $this->ensureActiveSigningKey();
        $now  = time();
        $keys = [];

        foreach (array_reverse($this->keyRepo()->findAll()) as $key) {
            if ($key->isPublishable($now)) {
                $keys[] = $key->publicJwk;
            }
        }

        return ['keys' => $keys];
    }


    // -------------------------------------------------------------------------
    // API-managed public key entries
    // -------------------------------------------------------------------------

    /**
     * @return FederationKey[]
     */
    public function listKeys(): array
    {
        $this->ensureActiveSigningKey();

        return $this->keyRepo()->findAll();
    }


    public function findKey(string $kid): ?FederationKey
    {
        $this->ensureActiveSigningKey();

        return $this->keyRepo()->findByKid($kid);
    }


    /**
     * Add an externally-held public key to the published set.
     *
     * @param array<string,mixed> $jwkData
     * @throws InvalidArgumentException When the JWK is invalid or the kid already exists.
     */
    public function addPublicKey(array $jwkData, ?int $iat, ?int $nbf, ?int $exp): FederationKey
    {
        $decorator = $this->parsePublicJwk($jwkData);
        $kid       = $this->kidOf($decorator, $jwkData);

        if ($this->keyRepo()->findByKid($kid) !== null) {
            throw new InvalidArgumentException(sprintf('A key with kid "%s" already exists.', $kid));
        }

        $publicJwk        = $decorator->jwk()->toPublic()->jsonSerialize();
        $publicJwk['kid'] = $kid;

        $key = new FederationKey(
            id:               null,
            kid:              $kid,
            privateJwk:       null,
            publicJwk:        $publicJwk,
            alg:              isset($jwkData['alg']) ? (string) $jwkData['alg'] : null,
            kmsManaged:       false,
            status:           'active',
            iat:              $iat ?? time(),
            nbf:              $nbf,
            exp:              $exp,
            revokedAt:        null,
            revocationReason: null,
            createdAt:        time(),
        );

        $this->keyRepo()->create($key);
        Logger::info(sprintf('oidanchor: public key added: %s', $kid));

        return $this->keyRepo()->findByKid($kid) ?? $key;
    }


    public function updateKeyValidity(string $kid, ?int $nbf, ?int $exp, bool $setNbf, bool $setExp): ?FederationKey
    {
        $repo = $this->keyRepo();
        if ($repo->findByKid($kid) === null) {
            return null;
        }

        $repo->updateValidity($kid, $nbf, $exp, $setNbf, $setExp);
        Logger::info(sprintf('oidanchor: public key metadata updated: %s', $kid));

        return $repo->findByKid($kid);
    }


    /**
     * Rotate a key entry: the replacement key is inserted and the old key is marked expired
     * (at old_key_exp, or immediately). Rotating the active signing key requires the new key
     * to carry private material, so API rotation of the signing key is rejected — use
     * triggerRotation() for that.
     *
     * @param array<string,mixed> $newJwkData
     * @throws InvalidArgumentException
     */
    public function rotateKey(string $kid, array $newJwkData, ?int $iat, ?int $nbf, ?int $exp, ?int $oldKeyExp): ?FederationKey
    {
        $repo = $this->keyRepo();
        $old  = $repo->findByKid($kid);
        if ($old === null) {
            return null;
        }

        if ($old->kmsManaged) {
            throw new InvalidArgumentException(
                'This kid is the KMS-managed signing key; rotate it via POST /kms/rotate.',
            );
        }

        $new = $this->addPublicKey($newJwkData, $iat, $nbf, $exp);
        $repo->markExpired($kid, $oldKeyExp ?? time());
        Logger::info(sprintf('oidanchor: public key rotated: %s -> %s', $kid, $new->kid));

        return $new;
    }


    /**
     * Delete or revoke a key entry. Returns false when the kid does not exist.
     *
     * @throws InvalidArgumentException When targeting the active signing key.
     */
    public function deleteKey(string $kid, bool $revoke, ?string $reason): bool
    {
        $repo = $this->keyRepo();
        $key  = $repo->findByKid($kid);
        if ($key === null) {
            return false;
        }

        $active = $repo->findActiveSigningKey();
        if ($active !== null && $active->kid === $kid) {
            throw new InvalidArgumentException(
                'Cannot delete or revoke the active signing key; rotate it first (POST /kms/rotate).',
            );
        }

        if ($revoke) {
            $repo->revoke($kid, $reason);
            Logger::info(sprintf('oidanchor: key revoked: %s (%s)', $kid, $reason ?? 'no reason'));
        } else {
            $repo->hardDelete($kid);
            Logger::info(sprintf('oidanchor: key deleted: %s', $kid));
        }

        return true;
    }


    // -------------------------------------------------------------------------
    // KMS info / algorithm / rotation
    // -------------------------------------------------------------------------

    /**
     * @return array<string,mixed>
     */
    public function kmsInfo(): array
    {
        $this->ensureActiveSigningKey();

        return [
            'kms'         => 'database',
            'alg'         => $this->configuredAlgorithm(),
            'rsa_key_len' => $this->rsaKeyLen(),
            'rotation'    => $this->rotationOptions(),
        ];
    }


    /**
     * Switch the signing algorithm. When the current signing key cannot serve the new
     * algorithm (different kty / curve), a new signing key is generated immediately and
     * the old one is rotated out, so the change takes effect without restarts.
     *
     * The spec's SignatureAlgorithm enum also lists the symmetric HS* algorithms; the library's
     * SignatureAlgorithmEnum does not model them (they cannot produce a public JWKS), so they
     * are rejected here along with `none`.
     *
     * @throws InvalidArgumentException For algorithms the federation cannot sign with.
     */
    public function setAlgorithm(string $alg): void
    {
        $enum = SignatureAlgorithmEnum::tryFrom($alg);

        if ($enum === null || $enum === SignatureAlgorithmEnum::none) {
            throw new InvalidArgumentException(sprintf(
                'Unsupported signature algorithm "%s". Supported: %s.',
                $alg,
                implode(', ', array_filter(
                    array_column(SignatureAlgorithmEnum::cases(), 'value'),
                    static fn(string $value): bool => $value !== 'none',
                )),
            ));
        }

        $this->settingsRepo()->set(SettingsRepository::SIGNING_ALGORITHM, $enum->value);

        $active = $this->ensureActiveSigningKey();
        if ($this->keyServesAlgorithm($active, $enum)) {
            $this->keyRepo()->updateAlg($active->kid, $enum->value);
        } else {
            $this->rotateSigningKey(false, sprintf('algorithm switched to %s', $enum->value));
        }

        Logger::info(sprintf('oidanchor: signing algorithm set to %s', $enum->value));
    }


    /**
     * @throws InvalidArgumentException
     */
    public function setRsaKeyLen(int $bits): void
    {
        if ($bits < 2048 || $bits > 8192 || $bits % 8 !== 0) {
            throw new InvalidArgumentException('rsa_key_len must be a multiple of 8 between 2048 and 8192.');
        }

        $this->settingsRepo()->set(SettingsRepository::RSA_KEY_LEN, $bits);
        Logger::info(sprintf('oidanchor: RSA key length set to %d', $bits));
    }


    /**
     * @return array{enabled: bool, interval: int, overlap: int}
     */
    public function rotationOptions(): array
    {
        $stored = $this->settingsRepo()->getArray(SettingsRepository::KMS_ROTATION, []) ?? [];

        return [
            'enabled'  => (bool) ($stored['enabled'] ?? false),
            'interval' => (int) ($stored['interval'] ?? 0),
            'overlap'  => (int) ($stored['overlap'] ?? self::DEFAULT_ROTATION_OVERLAP),
        ];
    }


    /**
     * @param array<string,mixed> $options Full replacement (PUT) or partial (PATCH via $merge).
     * @return array{enabled: bool, interval: int, overlap: int}
     * @throws InvalidArgumentException
     */
    public function setRotationOptions(array $options, bool $merge): array
    {
        $current = $merge ? $this->rotationOptions() : ['enabled' => false, 'interval' => 0, 'overlap' => 0];

        foreach (['enabled', 'interval', 'overlap'] as $field) {
            if (!array_key_exists($field, $options)) {
                continue;
            }
            if ($field === 'enabled' && !is_bool($options['enabled'])) {
                throw new InvalidArgumentException('enabled must be a boolean.');
            }
            if ($field !== 'enabled' && (!is_int($options[$field]) || $options[$field] < 0)) {
                throw new InvalidArgumentException(sprintf('%s must be a non-negative integer.', $field));
            }
            $current[$field] = $options[$field];
        }

        if ($current['enabled'] && $current['interval'] < 1) {
            throw new InvalidArgumentException('interval must be positive when rotation is enabled.');
        }

        $this->settingsRepo()->set(SettingsRepository::KMS_ROTATION, $current);
        Logger::info('oidanchor: KMS rotation options updated');

        return $current;
    }


    /**
     * Manually rotate the KMS signing key: generate a fresh key pair for the configured
     * algorithm, activate it, and expire (or revoke) the previous key.
     */
    public function triggerRotation(bool $revokeOld, ?string $reason): FederationKey
    {
        $this->ensureActiveSigningKey();

        return $this->rotateSigningKey($revokeOld, $reason);
    }


    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private function ensureActiveSigningKey(): FederationKey
    {
        $repo   = $this->keyRepo();
        $active = $repo->findActiveSigningKey();
        if ($active !== null) {
            return $active;
        }

        // First use: import the config-file key so existing deployments keep their key.
        $keyFile = $this->moduleConfig->getString('signing_key_file');
        $keyPass = $this->moduleConfig->getOptionalString('signing_key_passphrase', null);

        $decorator = (new Jwk())->jwkDecoratorFactory()->fromPkcs1Or8KeyFile($keyFile, $keyPass, ['use' => 'sig']);

        $imported = $this->storeSigningKey($decorator, $this->configuredAlgorithm());
        Logger::info(sprintf('oidanchor: config signing key imported into key store: %s', $imported->kid));

        return $imported;
    }


    /**
     * Interval-based rotation: when enabled and the active key is older than the interval,
     * rotate on access (the module has no scheduler, so rotation is applied opportunistically).
     */
    private function maybeAutoRotate(FederationKey $active): FederationKey
    {
        $options = $this->rotationOptions();
        if (!$options['enabled'] || $options['interval'] < 1) {
            return $active;
        }

        $issuedAt = $active->iat ?? $active->createdAt;
        if ($issuedAt + $options['interval'] > time()) {
            return $active;
        }

        return $this->rotateSigningKey(false, 'automatic rotation');
    }


    private function rotateSigningKey(bool $revokeOld, ?string $reason): FederationKey
    {
        $repo    = $this->keyRepo();
        $old     = $repo->findActiveSigningKey();
        $alg     = SignatureAlgorithmEnum::from($this->configuredAlgorithm());
        $keyData = $this->generateKeyData($alg);

        $decorator = (new Jwk())->jwkDecoratorFactory()->fromData($keyData);
        $new       = $this->storeSigningKey($decorator, $alg->value);

        if ($old !== null) {
            if ($revokeOld) {
                $repo->revoke($old->kid, $reason);
            } else {
                $overlap = $this->rotationOptions()['overlap'];
                $repo->markExpired($old->kid, time() + max(0, $overlap));
            }
        }

        Logger::info(sprintf(
            'oidanchor: signing key rotated: %s -> %s (%s)',
            $old?->kid ?? 'none',
            $new->kid,
            $reason ?? 'manual',
        ));

        return $new;
    }


    private function storeSigningKey(JwkDecorator $decorator, string $alg): FederationKey
    {
        $publicJwk = $decorator->jwk()->toPublic();
        $kid       = (string) ($publicJwk->jsonSerialize()['kid'] ?? $publicJwk->thumbprint('sha256'));

        $publicData        = $publicJwk->jsonSerialize();
        $publicData['kid'] = $kid;
        $publicData['use'] = $publicData['use'] ?? 'sig';

        $privateData        = $decorator->jwk()->jsonSerialize();
        $privateData['kid'] = $kid;

        $key = new FederationKey(
            id:               null,
            kid:              $kid,
            privateJwk:       $privateData,
            publicJwk:        $publicData,
            alg:              $alg,
            kmsManaged:       true,
            status:           'active',
            iat:              time(),
            nbf:              null,
            exp:              null,
            revokedAt:        null,
            revocationReason: null,
            createdAt:        time(),
        );

        $this->keyRepo()->create($key);

        return $this->keyRepo()->findByKid($kid) ?? $key;
    }


    /**
     * Generate raw JWK data for the given algorithm.
     *
     * Uses web-token's JWKFactory directly: simplesamlphp/openid has no key generation
     * (its JwkDecoratorFactory only loads existing material), and JWKFactory is the class
     * the library itself builds on.
     *
     * @return array<string,mixed>
     */
    private function generateKeyData(SignatureAlgorithmEnum $alg): array
    {
        $values = ['use' => 'sig', 'alg' => $alg->value];

        $jwk = match ($alg) {
            SignatureAlgorithmEnum::RS256, SignatureAlgorithmEnum::RS384, SignatureAlgorithmEnum::RS512,
            SignatureAlgorithmEnum::PS256, SignatureAlgorithmEnum::PS384, SignatureAlgorithmEnum::PS512
                => JWKFactory::createRSAKey($this->rsaKeyLen(), $values),
            SignatureAlgorithmEnum::ES256 => JWKFactory::createECKey('P-256', $values),
            SignatureAlgorithmEnum::ES384 => JWKFactory::createECKey('P-384', $values),
            SignatureAlgorithmEnum::ES512 => JWKFactory::createECKey('P-521', $values),
            SignatureAlgorithmEnum::EdDSA => JWKFactory::createOKPKey('Ed25519', $values),
            SignatureAlgorithmEnum::none  => throw new InvalidArgumentException(
                'The "none" algorithm cannot sign federation objects.',
            ),
        };

        return $jwk->all();
    }


    private function keyServesAlgorithm(FederationKey $key, SignatureAlgorithmEnum $alg): bool
    {
        $kty = (string) ($key->publicJwk['kty'] ?? '');
        $crv = (string) ($key->publicJwk['crv'] ?? '');

        return match ($alg) {
            SignatureAlgorithmEnum::RS256, SignatureAlgorithmEnum::RS384, SignatureAlgorithmEnum::RS512,
            SignatureAlgorithmEnum::PS256, SignatureAlgorithmEnum::PS384, SignatureAlgorithmEnum::PS512
                => $kty === 'RSA',
            SignatureAlgorithmEnum::ES256 => $kty === 'EC' && $crv === 'P-256',
            SignatureAlgorithmEnum::ES384 => $kty === 'EC' && $crv === 'P-384',
            SignatureAlgorithmEnum::ES512 => $kty === 'EC' && $crv === 'P-521',
            SignatureAlgorithmEnum::EdDSA => $kty === 'OKP',
            SignatureAlgorithmEnum::none  => false,
        };
    }


    /**
     * @param array<string,mixed> $jwkData
     * @throws InvalidArgumentException
     */
    private function parsePublicJwk(array $jwkData): JwkDecorator
    {
        if (!isset($jwkData['kty']) || !is_string($jwkData['kty'])) {
            throw new InvalidArgumentException('JWK must contain a "kty" member.');
        }

        try {
            return (new Jwk())->jwkDecoratorFactory()->fromData($jwkData);
        } catch (\Throwable $e) {
            throw new InvalidArgumentException('Invalid JWK: ' . $e->getMessage(), 0, $e);
        }
    }


    /**
     * @param array<string,mixed> $jwkData
     */
    private function kidOf(JwkDecorator $decorator, array $jwkData): string
    {
        $kid = isset($jwkData['kid']) && is_string($jwkData['kid']) ? trim($jwkData['kid']) : '';

        return $kid !== '' ? $kid : $decorator->jwk()->toPublic()->thumbprint('sha256');
    }


    private function configuredAlgorithm(): string
    {
        return $this->settingsRepo()->getString(SettingsRepository::SIGNING_ALGORITHM)
            ?? $this->moduleConfig->getOptionalString('signing_algorithm', 'RS256')
            ?? 'RS256';
    }


    private function rsaKeyLen(): int
    {
        return $this->settingsRepo()->getInt(SettingsRepository::RSA_KEY_LEN)
            ?? $this->moduleConfig->getOptionalInteger('signing_rsa_key_len', self::DEFAULT_RSA_KEY_LEN)
            ?? self::DEFAULT_RSA_KEY_LEN;
    }


    private function settingsRepo(): SettingsRepository
    {
        return $this->settings ??= new SettingsRepository($this->pdo);
    }


    private function keyRepo(): FederationKeyRepository
    {
        return $this->keys ??= new FederationKeyRepository($this->pdo);
    }
}
