<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Database;

use RuntimeException;
use SimpleSAML\Configuration;

/**
 * Encryption at rest for the federation private keys in the key store.
 *
 * With `key_store_secret` configured, each private JWK is sealed with AES-256-GCM under a key
 * derived from the secret (HKDF-SHA256), with the key's kid as associated data so a ciphertext
 * cannot be moved onto another key's row. Stored form: "enc:v1:" + base64(iv . tag . ciphertext).
 *
 * Without a secret, values are stored and read as plain JSON (the pre-encryption behaviour).
 * A sealed value can never be read without the secret.
 */
final class KeyMaterialCipher
{
    private const string PREFIX = 'enc:v1:';

    private const string ALGORITHM = 'aes-256-gcm';

    private const int IV_LENGTH = 12;

    private const int TAG_LENGTH = 16;

    private const int MIN_SECRET_LENGTH = 32;


    private function __construct(
        private readonly ?string $key,
    ) {
    }


    /**
     * @throws \RuntimeException When the configured secret is too short to be a real secret.
     */
    public static function fromConfig(Configuration $moduleConfig): self
    {
        $secret = $moduleConfig->getOptionalString('key_store_secret', null);
        if ($secret === null || $secret === '') {
            return new self(null);
        }

        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new RuntimeException(sprintf(
                'oidanchor: key_store_secret must be at least %d characters long.',
                self::MIN_SECRET_LENGTH,
            ));
        }

        return new self(hash_hkdf('sha256', $secret, 32, 'oidanchor key store v1'));
    }


    /**
     * A cipher that stores key material as plain JSON (no secret configured).
     */
    public static function disabled(): self
    {
        return new self(null);
    }


    public function isEnabled(): bool
    {
        return $this->key !== null;
    }


    public static function isSealed(string $stored): bool
    {
        return str_starts_with($stored, self::PREFIX);
    }


    /**
     * Seal a private JWK (JSON) for storage; returned unchanged when no secret is configured.
     */
    public function seal(string $plaintext, string $kid): string
    {
        if ($this->key === null) {
            return $plaintext;
        }

        $iv         = random_bytes(self::IV_LENGTH);
        $tag        = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $kid,
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new RuntimeException('oidanchor: could not encrypt key material.');
        }

        return self::PREFIX . base64_encode($iv . $tag . $ciphertext);
    }


    /**
     * Read a stored private JWK back to JSON. Plain (legacy) values pass through.
     *
     * @throws \RuntimeException When the value is sealed and cannot be opened (no secret, the
     *     wrong secret, or tampered data).
     */
    public function open(string $stored, string $kid): string
    {
        if (!self::isSealed($stored)) {
            return $stored;
        }

        if ($this->key === null) {
            throw new RuntimeException(
                'oidanchor: the key store is encrypted but key_store_secret is not configured.',
            );
        }

        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= self::IV_LENGTH + self::TAG_LENGTH) {
            throw new RuntimeException(sprintf('oidanchor: malformed encrypted key material for kid "%s".', $kid));
        }

        $plaintext = openssl_decrypt(
            substr($raw, self::IV_LENGTH + self::TAG_LENGTH),
            self::ALGORITHM,
            $this->key,
            OPENSSL_RAW_DATA,
            substr($raw, 0, self::IV_LENGTH),
            substr($raw, self::IV_LENGTH, self::TAG_LENGTH),
            $kid,
        );

        if ($plaintext === false) {
            throw new RuntimeException(sprintf(
                'oidanchor: cannot decrypt the private key "%s" (wrong key_store_secret or tampered data).',
                $kid,
            ));
        }

        return $plaintext;
    }
}
