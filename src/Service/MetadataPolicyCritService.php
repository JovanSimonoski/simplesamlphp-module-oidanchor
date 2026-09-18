<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use PDO;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\OpenID\Codebooks\MetadataPolicyOperatorsEnum;

/**
 * The `metadata_policy_crit` claim: metadata policy operators that a consumer MUST understand
 * to process the subordinate statement (OpenID Federation 1.0 §6.2).
 *
 * Operator names are validated against the library's MetadataPolicyOperatorsEnum, so only
 * operators the federation actually defines can be marked critical.
 */
class MetadataPolicyCritService
{
    public function __construct(private readonly PDO $pdo)
    {
    }


    /**
     * @return list<string>
     */
    public function all(): array
    {
        /** @var list<string> $operators */
        $operators = (new SettingsRepository($this->pdo))->getArray(SettingsRepository::METADATA_POLICY_CRIT, []) ?? [];

        return $operators;
    }


    /**
     * Replace the critical operator list.
     *
     * @param array<mixed> $operators
     * @return list<string>
     * @throws InvalidArgumentException When an operator is unknown or the list is malformed.
     */
    public function replace(array $operators): array
    {
        if (!array_is_list($operators)) {
            throw new InvalidArgumentException('Body must be a JSON array of operator names.');
        }

        $validated = [];
        foreach ($operators as $operator) {
            $validated[] = self::assertKnownOperator($operator);
        }

        $validated = array_values(array_unique($validated));
        (new SettingsRepository($this->pdo))->set(SettingsRepository::METADATA_POLICY_CRIT, $validated);

        return $validated;
    }


    /**
     * Add one operator. Returns false when it was already present.
     *
     * @throws InvalidArgumentException When the operator is unknown.
     */
    public function add(mixed $operator): bool
    {
        $name    = self::assertKnownOperator($operator);
        $current = $this->all();

        if (in_array($name, $current, true)) {
            return false;
        }

        $current[] = $name;
        (new SettingsRepository($this->pdo))->set(SettingsRepository::METADATA_POLICY_CRIT, $current);

        return true;
    }


    public function remove(string $operator): void
    {
        $remaining = array_values(array_filter(
            $this->all(),
            static fn(string $known): bool => $known !== $operator,
        ));

        (new SettingsRepository($this->pdo))->set(SettingsRepository::METADATA_POLICY_CRIT, $remaining);
    }


    /**
     * @throws InvalidArgumentException
     */
    private static function assertKnownOperator(mixed $operator): string
    {
        if (!is_string($operator) || MetadataPolicyOperatorsEnum::tryFrom($operator) === null) {
            throw new InvalidArgumentException(sprintf(
                'Unknown metadata policy operator "%s". Known operators: %s.',
                is_string($operator) ? $operator : gettype($operator),
                implode(', ', MetadataPolicyOperatorsEnum::values()),
            ));
        }

        return $operator;
    }
}
