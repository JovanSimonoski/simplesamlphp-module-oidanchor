<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use SimpleSAML\Module\oidanchor\Database\Upsert;

/**
 * Fixed-window request counters, used to rate-limit the public endpoints that do outbound work.
 * Buckets are opaque strings chosen by the caller (hash client identifiers before using them).
 */
class RateLimitRepository
{
    private const string TABLE = 'oidanchor_rate_limits';


    public function __construct(private readonly PDO $pdo)
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS ' . self::TABLE . ' (
                bucket       TEXT    NOT NULL PRIMARY KEY,
                window_start INTEGER NOT NULL,
                hits         INTEGER NOT NULL
            )',
        );
    }


    /**
     * Count one request in $bucket and report whether it is within $limit per $window seconds.
     *
     * @return int|null Null when allowed; otherwise the seconds until the window resets.
     */
    public function hit(string $bucket, int $limit, int $window, ?int $now = null): ?int
    {
        $now ??= time();

        $stmt = $this->pdo->prepare('SELECT window_start, hits FROM ' . self::TABLE . ' WHERE bucket = ?');
        $stmt->execute([$bucket]);

        /** @var array{window_start: int|string, hits: int|string}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false || (int) $row['window_start'] + $window <= $now) {
            // A new window: forget windows that have ended, so the table stays small.
            $this->pdo->prepare('DELETE FROM ' . self::TABLE . ' WHERE window_start + ? <= ?')->execute([$window, $now]);
            Upsert::run($this->pdo, self::TABLE, ['bucket' => $bucket], ['window_start' => $now, 'hits' => 1]);

            return $limit >= 1 ? null : $window;
        }

        $hits = (int) $row['hits'] + 1;
        $this->pdo->prepare('UPDATE ' . self::TABLE . ' SET hits = ? WHERE bucket = ?')->execute([$hits, $bucket]);

        return $hits <= $limit ? null : max(1, (int) $row['window_start'] + $window - $now);
    }
}
