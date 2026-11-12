<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Database\Upsert;

/**
 * Signed Resolve Responses kept for a short while, so repeated /resolve requests for the same
 * subject do not each walk (and fetch) the whole trust chain again.
 */
class ResolveCacheRepository
{
    private const string TABLE = 'oidanchor_resolve_cache';


    public function __construct(private readonly PDO $pdo)
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                cache_key  TEXT    NOT NULL PRIMARY KEY,
                response   TEXT    NOT NULL,
                expires_at INTEGER NOT NULL
            )',
        );
    }


    public static function keyFor(string $sub, string $trustAnchor, ?string $entityType): string
    {
        return hash('sha256', (string) json_encode([$sub, $trustAnchor, $entityType]));
    }


    public function get(string $key, ?int $now = null): ?string
    {
        $stmt = $this->pdo->prepare('SELECT response FROM ' . self::TABLE . ' WHERE cache_key = ? AND expires_at > ?');
        $stmt->execute([$key, $now ?? time()]);
        $response = $stmt->fetchColumn();

        return is_string($response) ? $response : null;
    }


    public function put(string $key, string $response, int $expiresAt): void
    {
        $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE expires_at <= ?')->execute([time()]);
        Upsert::run($this->pdo, self::TABLE, ['cache_key' => $key], ['response' => $response, 'expires_at' => $expiresAt]);
    }
}
