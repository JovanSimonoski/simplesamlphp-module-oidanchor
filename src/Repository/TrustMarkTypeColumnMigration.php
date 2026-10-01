<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Repository;

use PDO;
use WeakMap;

/**
 * One-shot rename of the legacy `trust_mark_id` column to `trust_mark_type` on the issued-marks
 * and type-catalog tables (the column always held a trust_mark_type value).
 *
 * Called by every repository that reads either table, because those repositories can be
 * constructed before the owning one in a request. Idempotent: a table that is missing or already
 * renamed is left alone. Requires SQLite >= 3.25 (RENAME COLUMN).
 */
final class TrustMarkTypeColumnMigration
{
    private const TABLES = ['oidanchor_trust_marks_issued', 'oidanchor_trust_mark_types'];

    /** @var WeakMap<PDO, true>|null Connections already migrated in this request. */
    private static ?WeakMap $done = null;


    public static function run(PDO $pdo): void
    {
        self::$done ??= new WeakMap();
        if (isset(self::$done[$pdo])) {
            return;
        }

        foreach (self::TABLES as $table) {
            $columns = array_column(
                $pdo->query('PRAGMA table_info(' . $table . ')')->fetchAll(PDO::FETCH_ASSOC),
                'name',
            );

            if (in_array('trust_mark_id', $columns, true) && !in_array('trust_mark_type', $columns, true)) {
                $pdo->exec('ALTER TABLE ' . $table . ' RENAME COLUMN trust_mark_id TO trust_mark_type');
            }
        }

        self::$done[$pdo] = true;
    }
}
