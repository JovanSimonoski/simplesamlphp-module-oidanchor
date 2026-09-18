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
 * subordinate row. When both exist the per-subordinate value wins per member.
 *
 * simplesamlphp/openid models no constraints (no `constraints`, `max_path_length`,
 * `naming_constraints` or `allowed_entity_types` cases in Codebooks\ClaimsEnum, and no
 * validator in Federation\*), so the claim names are written literally and validated here.
 */
class ConstraintsService
{
    public const MAX_PATH_LENGTH = 'max_path_length';
    public const NAMING_CONSTRAINTS = 'naming_constraints';
    public const ALLOWED_ENTITY_TYPES = 'allowed_entity_types';

    public const CLAIM = 'constraints';


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
            'constraints' => $constraints === []
                ? null
                : json_encode($constraints, JSON_UNESCAPED_SLASHES),
            'updated_at'  => time(),
        ]);
    }


    /**
     * The effective constraints for a subordinate statement: general constraints overlaid
     * with the per-subordinate ones (per-subordinate wins per member). Returns null when
     * nothing is configured, so the claim is omitted.
     *
     * @return array<string,mixed>|null
     */
    public function effective(Subordinate $subordinate): ?array
    {
        $merged = array_merge($this->general(), $this->forSubordinate($subordinate));

        return $merged === [] ? null : $merged;
    }


    /**
     * Validate a whole Constraints object.
     *
     * @param array<string,mixed> $constraints
     * @throws InvalidArgumentException
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
     * @throws InvalidArgumentException
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
     * @throws InvalidArgumentException
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
            $out[$member] = array_values($value[$member]);
        }

        return $out;
    }


    /**
     * @return list<string>
     * @throws InvalidArgumentException
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
