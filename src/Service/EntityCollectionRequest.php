<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Module\oidanchor\Exception\EntityCollectionException;

/**
 * A parsed Entity Collection request (OpenID Federation Entity Collection 1.0, section 3.1).
 *
 * Several parameters may be repeated (`entity_type=a&entity_type=b`). PHP's own query parsing
 * keeps only the last value of a repeated name, so requests are parsed from the raw
 * application/x-www-form-urlencoded string with {@see parseFormEncoded()}.
 */
final class EntityCollectionRequest
{
    /** Entity Info claims this responder can return. */
    public const array ENTITY_CLAIMS = ['entity_id', 'entity_types', 'entity_infos', 'trust_marks'];

    /** Entity Info claims returned when the request has no entity_claims parameter. */
    public const array DEFAULT_ENTITY_CLAIMS = ['entity_id', 'entity_types', 'entity_infos'];

    /** Informational metadata claims (OpenID Federation 1.0, section 5.2.2) copied into entity_infos. */
    public const array INFO_CLAIMS = [
        'organization_name',
        'display_name',
        'description',
        'keywords',
        'contacts',
        'logo_uri',
        'policy_uri',
        'information_uri',
        'organization_uri',
    ];


    /**
     * @param list<string> $entityTypes Match any of these (OR).
     * @param list<string> $trustMarkTypes Match all of these (AND).
     * @param list<string>|null $entityClaims Requested Entity Info claims; null = the defaults.
     * @param list<string>|null $infoClaims Requested Entity Type Info claims; null = all.
     * @param list<string> $locales Lowercased language ranges; empty = all languages.
     */
    public function __construct(
        public readonly ?string $from = null,
        public readonly ?int $limit = null,
        public readonly array $entityTypes = [],
        public readonly array $trustMarkTypes = [],
        public readonly ?string $trustAnchor = null,
        public readonly ?string $query = null,
        public readonly ?array $entityClaims = null,
        public readonly ?array $infoClaims = null,
        public readonly array $locales = [],
    ) {
    }


    /**
     * Split an application/x-www-form-urlencoded string, keeping every value of a repeated name.
     *
     * @return array<string,list<string>>
     */
    public static function parseFormEncoded(string $encoded): array
    {
        $params = [];

        foreach (explode('&', $encoded) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $params[urldecode($name)][] = urldecode($value);
        }

        return $params;
    }


    /**
     * @param array<string,list<string>> $params
     * @throws \SimpleSAML\Module\oidanchor\Exception\EntityCollectionException
     */
    public static function fromParameters(array $params): self
    {
        $limit = self::single($params, 'limit');
        if ($limit !== null && (!ctype_digit($limit) || (int) $limit < 1)) {
            throw EntityCollectionException::invalidRequest('limit must be an integer greater than zero.');
        }

        $entityClaims = null;
        if (isset($params['entity_claims'])) {
            $entityClaims = self::values($params, 'entity_claims');
            foreach ($entityClaims as $claim) {
                if (!in_array($claim, self::ENTITY_CLAIMS, true)) {
                    throw EntityCollectionException::unsupportedClaim(
                        sprintf('The entity claim "%s" is not supported.', $claim),
                    );
                }
            }
            $entityClaims = array_values(array_unique(['entity_id', ...$entityClaims]));
        }

        $infoClaims = null;
        if (isset($params['info_claims'])) {
            $infoClaims = self::values($params, 'info_claims');
            foreach ($infoClaims as $claim) {
                if (!in_array(explode('#', $claim, 2)[0], self::INFO_CLAIMS, true)) {
                    throw EntityCollectionException::unsupportedClaim(
                        sprintf('The info claim "%s" is not supported.', $claim),
                    );
                }
            }
        }

        $locales = array_map('strtolower', self::values($params, 'locale'));
        foreach ($locales as $locale) {
            if (preg_match('/^(\*|[a-z]{1,8}(-[a-z0-9]{1,8})*)$/', $locale) !== 1) {
                throw EntityCollectionException::invalidRequest(sprintf('"%s" is not a language range.', $locale));
            }
        }

        return new self(
            from:           self::single($params, 'from'),
            limit:          $limit !== null ? (int) $limit : null,
            entityTypes:    self::values($params, 'entity_type'),
            trustMarkTypes: self::values($params, 'trust_mark_type'),
            trustAnchor:    self::single($params, 'trust_anchor'),
            query:          self::single($params, 'query'),
            entityClaims:   $entityClaims,
            infoClaims:     $infoClaims,
            locales:        array_values(array_unique($locales)),
        );
    }


    public function wantsEntityClaim(string $claim): bool
    {
        return in_array($claim, $this->entityClaims ?? self::DEFAULT_ENTITY_CLAIMS, true);
    }


    /**
     * Whether an Entity Type Info claim (possibly language-tagged, `display_name#de`) is
     * requested and in one of the requested languages. Untagged claims are always in.
     */
    public function wantsInfoClaim(string $name): bool
    {
        [$base, $tag] = array_pad(explode('#', $name, 2), 2, null);

        $requested = $this->infoClaims === null
            || in_array($name, $this->infoClaims, true)
            || in_array($base, $this->infoClaims, true);
        if (!$requested) {
            return false;
        }

        if ($tag === null || $this->locales === []) {
            return true;
        }

        // RFC 4647 basic filtering: "en" matches "en" and "en-US", "*" matches everything.
        $tag = strtolower($tag);
        foreach ($this->locales as $range) {
            if ($range === '*' || $tag === $range || str_starts_with($tag, $range . '-')) {
                return true;
            }
        }

        return false;
    }


    /**
     * Non-empty values of a parameter, without duplicates.
     *
     * @param array<string,list<string>> $params
     * @return list<string>
     */
    private static function values(array $params, string $name): array
    {
        $values = array_filter(array_map('trim', $params[$name] ?? []), static fn(string $v): bool => $v !== '');

        return array_values(array_unique($values));
    }


    /**
     * @param array<string,list<string>> $params
     * @throws \SimpleSAML\Module\oidanchor\Exception\EntityCollectionException
     */
    private static function single(array $params, string $name): ?string
    {
        $values = self::values($params, $name);
        if (count($values) > 1) {
            throw EntityCollectionException::invalidRequest(sprintf('The %s parameter can only be given once.', $name));
        }

        return $values[0] ?? null;
    }
}
