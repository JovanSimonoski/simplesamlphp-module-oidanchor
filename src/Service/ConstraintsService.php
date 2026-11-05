<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use PDO;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;

/**
 * The `constraints` claim of issued subordinate statements (OpenID Federation 1.0 §3.1:
 * max_path_length, naming_constraints {permitted, excluded}, allowed_entity_types).
 *
 * The general constraints live in the settings store; per-subordinate constraints live on the
 * subordinate row. When both exist the per-subordinate value can only narrow the general one
 * (see {@see effective()}).
 *
 * simplesamlphp/openid models no constraints (no `constraints`, `max_path_length`,
 * `naming_constraints` or `allowed_entity_types` cases in Codebooks\ClaimsEnum, and no
 * validator in Federation\*), so the claim names are written literally and validated here.
 */
class ConstraintsService
{
    public const string MAX_PATH_LENGTH = 'max_path_length';

    public const string NAMING_CONSTRAINTS = 'naming_constraints';

    public const string ALLOWED_ENTITY_TYPES = 'allowed_entity_types';

    public const string CLAIM = 'constraints';


    public function __construct(private readonly PDO $pdo)
    {
    }


    /**
     * Federation-wide constraints (empty array when unset).
     *
     * @return array<string,mixed>
     */
    public function general(): array
    {
        return (new SettingsRepository($this->pdo))->getArray(SettingsRepository::GENERAL_CONSTRAINTS, []) ?? [];
    }


    /**
     * @param array<string,mixed> $constraints
     */
    public function setGeneral(array $constraints): void
    {
        (new SettingsRepository($this->pdo))->set(SettingsRepository::GENERAL_CONSTRAINTS, $constraints);
    }


    /**
     * Per-subordinate constraints (empty array when unset).
     *
     * @return array<string,mixed>
     */
    public function forSubordinate(Subordinate $subordinate): array
    {
        return $subordinate->constraints ?? [];
    }


    /**
     * @param array<string,mixed> $constraints
     */
    public function setForSubordinate(string $entityId, array $constraints): void
    {
        (new SubordinateRepository($this->pdo))->update($entityId, [
            'constraints' => $constraints === [] ? null : $constraints,
            'updated_at'  => time(),
        ]);
    }


    /**
     * The effective constraints for a subordinate statement: the general constraints narrowed
     * by the per-subordinate ones, so a per-subordinate value can tighten but never loosen a
     * federation-wide constraint. Returns null when nothing is configured, so the claim is omitted.
     *
     *  - max_path_length: the smaller value.
     *  - allowed_entity_types: the intersection.
     *  - naming_constraints.excluded: the union (more exclusions only narrow).
     *  - naming_constraints.permitted: the intersection of the name subtrees.
     *  - any other member: the per-subordinate value wins (no narrowing semantics are defined).
     *
     * @return array<string,mixed>|null
     */
    public function effective(Subordinate $subordinate): ?array
    {
        $general = $this->general();
        $own     = $this->forSubordinate($subordinate);
        $merged  = array_merge($general, $own);

        if (isset($general[self::MAX_PATH_LENGTH], $own[self::MAX_PATH_LENGTH])) {
            $merged[self::MAX_PATH_LENGTH] = min((int) $general[self::MAX_PATH_LENGTH], (int) $own[self::MAX_PATH_LENGTH]);
        }

        if (isset($general[self::ALLOWED_ENTITY_TYPES], $own[self::ALLOWED_ENTITY_TYPES])) {
            $merged[self::ALLOWED_ENTITY_TYPES] = array_values(array_intersect(
                (array) $general[self::ALLOWED_ENTITY_TYPES],
                (array) $own[self::ALLOWED_ENTITY_TYPES],
            ));
        }

        if (isset($general[self::NAMING_CONSTRAINTS], $own[self::NAMING_CONSTRAINTS])) {
            $merged[self::NAMING_CONSTRAINTS] = self::narrowNamingConstraints(
                (array) $general[self::NAMING_CONSTRAINTS],
                (array) $own[self::NAMING_CONSTRAINTS],
            );
        }

        return $merged === [] ? null : $merged;
    }


    /**
     * @param array<string,mixed> $general
     * @param array<string,mixed> $own
     * @return array<string,list<string>>
     */
    private static function narrowNamingConstraints(array $general, array $own): array
    {
        $out = [];

        if (isset($general['permitted'], $own['permitted'])) {
            $g = array_map('strval', (array) $general['permitted']);
            $s = array_map('strval', (array) $own['permitted']);

            // A name is permitted only if both sides permit it: keep each subtree that lies within
            // a subtree of the other side. An empty result permits nothing.
            $out['permitted'] = array_values(array_unique(array_merge(
                array_filter($s, static fn(string $x): bool => self::withinAny($x, $g)),
                array_filter($g, static fn(string $x): bool => self::withinAny($x, $s)),
            )));
        } elseif (isset($general['permitted']) || isset($own['permitted'])) {
            $out['permitted'] = array_values(array_map('strval', (array) ($own['permitted'] ?? $general['permitted'])));
        }

        if (isset($general['excluded']) || isset($own['excluded'])) {
            $out['excluded'] = array_values(array_unique(array_map('strval', array_merge(
                (array) ($general['excluded'] ?? []),
                (array) ($own['excluded'] ?? []),
            ))));
        }

        return $out;
    }


    /**
     * @param list<string> $subtrees
     */
    private static function withinAny(string $name, array $subtrees): bool
    {
        foreach ($subtrees as $subtree) {
            if (self::within($name, $subtree)) {
                return true;
            }
        }

        return false;
    }


    /**
     * Whether every name matched by $name is also matched by $subtree (OpenID Federation 1.0
     * §6.2.2): a host matches only itself, a constraint starting with a period matches any name
     * formed by adding labels in front of it.
     */
    private static function within(string $name, string $subtree): bool
    {
        $name    = strtolower($name);
        $subtree = strtolower($subtree);

        return $name === $subtree
            || (str_starts_with($subtree, '.') && str_ends_with($name, $subtree));
    }


    /**
     * Validate a whole Constraints object.
     *
     * @param array<string,mixed> $constraints
     * @throws \InvalidArgumentException
     */
    public function validate(array $constraints): void
    {
        foreach ($constraints as $member => $value) {
            match ($member) {
                self::MAX_PATH_LENGTH      => self::validateMaxPathLength($value),
                self::NAMING_CONSTRAINTS   => self::validateNamingConstraints($value),
                self::ALLOWED_ENTITY_TYPES => self::validateAllowedEntityTypes($value),
                // The spec explicitly allows additional constraint parameters.
                default => null,
            };
        }
    }


    /**
     * @throws \InvalidArgumentException
     */
    public static function validateMaxPathLength(mixed $value): int
    {
        if (!is_int($value) || $value < 0) {
            throw new InvalidArgumentException('max_path_length must be a non-negative integer.');
        }

        return $value;
    }


    /**
     * @return array<string,list<string>>
     * @throws \InvalidArgumentException
     */
    public static function validateNamingConstraints(mixed $value): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException('naming_constraints must be an object.');
        }

        $out = [];
        foreach (['permitted', 'excluded'] as $member) {
            if (!array_key_exists($member, $value)) {
                continue;
            }
            if (!is_array($value[$member]) || array_is_list($value[$member]) === false) {
                throw new InvalidArgumentException(sprintf('naming_constraints.%s must be an array of strings.', $member));
            }
            foreach ($value[$member] as $subtree) {
                if (!is_string($subtree) || trim($subtree) === '') {
                    throw new InvalidArgumentException(sprintf('naming_constraints.%s must contain non-empty strings.', $member));
                }
            }
            $out[$member] = $value[$member];
        }

        return $out;
    }


    /**
     * @return list<string>
     * @throws \InvalidArgumentException
     */
    public static function validateAllowedEntityTypes(mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidArgumentException('allowed_entity_types must be an array of entity type identifiers.');
        }

        foreach ($value as $entityType) {
            if (!is_string($entityType) || trim($entityType) === '') {
                throw new InvalidArgumentException('allowed_entity_types must contain non-empty strings.');
            }
        }

        return array_values(array_unique($value));
    }
}
