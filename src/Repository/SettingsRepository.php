<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;

/**
 * Key/value store for runtime-mutable settings written through the Federation Admin API
 * (lifetimes, signing algorithm, RSA key length, KMS rotation options, metadata_policy_crit,
 * general constraints, ...). Values are stored as JSON.
 *
 * A setting that has never been written is absent; callers fall back to the module config
 * default, so the config file keeps working as the initial state.
 */
class SettingsRepository
{
    private const TABLE = 'oidanchor_settings';

    public const ENTITY_CONFIGURATION_LIFETIME = 'entity_configuration_lifetime';
    public const SUBORDINATE_STATEMENT_LIFETIME = 'subordinate_statement_lifetime';
    public const SIGNING_ALGORITHM = 'signing_algorithm';
    public const RSA_KEY_LEN = 'rsa_key_len';
    public const KMS_ROTATION = 'kms_rotation';
    public const METADATA_POLICY_CRIT = 'metadata_policy_crit';
    public const GENERAL_CONSTRAINTS = 'general_constraints';


    public function __construct(private readonly PDO $pdo)
    {
        $this->ensureSchema();
    }


    private function ensureSchema(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                setting_key   TEXT    NOT NULL PRIMARY KEY,
                setting_value TEXT    NOT NULL,
                updated_at    INTEGER NOT NULL
            )',
        );
    }


    /**
     * Return the JSON-decoded value, or null when the setting was never written.
     */
    public function get(string $key): mixed
    {
        $stmt = $this->pdo->prepare(
            'SELECT setting_value FROM ' . self::TABLE . ' WHERE setting_key = ?',
        );
        $stmt->execute([$key]);

        $value = $stmt->fetchColumn();

        return $value === false ? null : json_decode((string) $value, true);
    }


    public function getInt(string $key, ?int $default = null): ?int
    {
        $value = $this->get($key);

        return is_int($value) ? $value : $default;
    }


    public function getString(string $key, ?string $default = null): ?string
    {
        $value = $this->get($key);

        return is_string($value) ? $value : $default;
    }


    /**
     * @param array<mixed>|null $default
     * @return array<mixed>|null
     */
    public function getArray(string $key, ?array $default = null): ?array
    {
        $value = $this->get($key);

        return is_array($value) ? $value : $default;
    }


    public function set(string $key, mixed $value): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ' . self::TABLE . ' (setting_key, setting_value, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(setting_key) DO UPDATE SET
                 setting_value = excluded.setting_value,
                 updated_at    = excluded.updated_at',
        );
        $stmt->execute([$key, json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), time()]);
    }


    public function delete(string $key): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM ' . self::TABLE . ' WHERE setting_key = ?',
        );
        $stmt->execute([$key]);
    }
}
