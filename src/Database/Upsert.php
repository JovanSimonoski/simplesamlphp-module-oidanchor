<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Database;

use PDO;

/**
 * Insert-or-update in standard SQL. `INSERT ... ON CONFLICT` (SQLite, PostgreSQL),
 * `ON DUPLICATE KEY UPDATE` (MySQL) and `INSERT OR IGNORE` (SQLite) are each engine-specific,
 * so the row is looked up by its key first and then updated or inserted.
 *
 * Table and column names come from the repositories, never from input.
 */
final class Upsert
{
    /**
     * @param array<string,mixed> $key        Column => value pairs identifying the row.
     * @param array<string,mixed> $values     Columns written on insert and on update. Empty means
     *                                        "insert if missing, otherwise leave the row alone".
     * @param array<string,mixed> $insertOnly Columns written only when the row is created (e.g. created_at).
     */
    public static function run(PDO $pdo, string $table, array $key, array $values, array $insertOnly = []): void
    {
        $where = implode(' AND ', array_map(static fn(string $col): string => $col . ' = ?', array_keys($key)));

        $exists = $pdo->prepare('SELECT 1 FROM ' . $table . ' WHERE ' . $where);
        $exists->execute(array_values($key));

        if ($exists->fetchColumn() !== false) {
            if ($values === []) {
                return;
            }

            $sets = implode(', ', array_map(static fn(string $col): string => $col . ' = ?', array_keys($values)));
            $pdo->prepare('UPDATE ' . $table . ' SET ' . $sets . ' WHERE ' . $where)
                ->execute([...array_values($values), ...array_values($key)]);

            return;
        }

        $row = $key + $values + $insertOnly;
        $pdo->prepare(sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $table,
            implode(', ', array_keys($row)),
            implode(', ', array_fill(0, count($row), '?')),
        ))->execute(array_values($row));
    }
}
