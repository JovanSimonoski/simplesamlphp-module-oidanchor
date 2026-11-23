<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Entity\SubordinateStatus;
use SimpleSAML\Module\oidanchor\Exception\EntityCollectionException;
use SimpleSAML\Module\oidanchor\Repository\EntityCollectionRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use Throwable;

/**
 * The Entity Collection endpoint (OpenID Federation Entity Collection 1.0): the entities in this
 * federation, with the informational metadata a discovery service shows (display names, logos)
 * and their verified Trust Marks.
 *
 * Two halves, kept apart like the rest of the module:
 *  - {@see refresh()} runs from cron. It resolves the trust chain of every active subordinate to
 *    this Trust Anchor ({@see FederationResolver}: signatures, metadata policy, Trust Mark
 *    verification) and stores what it learns in {@see EntityCollectionRepository}.
 *  - {@see page()} answers the public request from the subordinate registry plus that snapshot:
 *    no outbound HTTP. Membership is always current; types, infos and Trust Marks are as of the
 *    last refresh. An entity whose chain did not resolve is still listed, with only what this
 *    Trust Anchor registered for it (entity_id and entity types).
 *
 * Only direct subordinates are collected; entities below intermediates are not traversed.
 *
 * @phpstan-type Snapshot array{
 *     entity_types: list<string>,
 *     entity_infos: array<string,array<string,mixed>>,
 *     trust_marks: list<array{trust_mark_type: string, trust_mark: string}>,
 * }
 * @phpstan-type Entry array{
 *     entity_id: string,
 *     entity_types: list<string>,
 *     entity_infos: array<string,array<string,mixed>>,
 *     trust_marks: list<array{trust_mark_type: string, trust_mark: string}>,
 * }
 */
class EntityCollectionService
{
    public const int DEFAULT_MAX_PAGE_SIZE = 100;

    /** Info claims searched by the query parameter. */
    private const array SEARCHED_CLAIMS = ['display_name', 'organization_name', 'description', 'keywords'];


    public function __construct(
        private readonly string $trustAnchor,
        private readonly SubordinateRepository $subordinates,
        private readonly EntityCollectionRepository $collection,
        private readonly SettingsRepository $settings,
        private readonly int $maxPageSize = self::DEFAULT_MAX_PAGE_SIZE,
    ) {
    }


    public static function fromConfig(Configuration $moduleConfig, PDO $pdo): self
    {
        $settings = $moduleConfig->getOptionalArray('collection', []);

        return new self(
            $moduleConfig->getString('entity_id'),
            new SubordinateRepository($pdo),
            new EntityCollectionRepository($pdo),
            new SettingsRepository($pdo),
            max(1, (int) ($settings['max_page_size'] ?? self::DEFAULT_MAX_PAGE_SIZE)),
        );
    }


    /**
     * Resolve every active subordinate and store its types, infos and verified Trust Marks.
     * A subordinate that does not resolve keeps no infos or Trust Marks from an earlier run.
     *
     * @return array{resolved: int, failed: int}
     */
    public function refresh(FederationResolver $resolver, ?int $now = null): array
    {
        $now    = $now ?? time();
        $counts = ['resolved' => 0, 'failed' => 0];
        $active = [];

        foreach ($this->activeSubordinates() as $subordinate) {
            $entityId = $subordinate->entityId;
            $active[] = $entityId;

            try {
                $result = $resolver->resolve($entityId, $this->trustAnchor);
                $this->collection->save(
                    $entityId,
                    array_map('strval', array_keys($result->metadata)),
                    self::entityInfos($result->metadata),
                    $result->trustMarks,
                    null,
                    $now,
                );
                $counts['resolved']++;
            } catch (Throwable $e) {
                Logger::warning(sprintf(
                    'oidanchor: entity collection could not resolve "%s": %s',
                    $entityId,
                    $e->getMessage(),
                ));
                $this->collection->save($entityId, [], [], [], $e->getMessage(), $now);
                $counts['failed']++;
            }
        }

        $this->collection->retainOnly($active);
        $this->settings->set(SettingsRepository::ENTITY_COLLECTION_REFRESHED_AT, $now);

        return $counts;
    }


    /**
     * One page of the collection for a request.
     *
     * @return array{entities: list<array<string,mixed>>, next?: string, last_updated?: int}
     * @throws \SimpleSAML\Module\oidanchor\Exception\EntityCollectionException
     */
    public function page(EntityCollectionRequest $request, ?int $now = null): array
    {
        $now = $now ?? time();

        if ($request->trustAnchor !== null && $request->trustAnchor !== $this->trustAnchor) {
            throw EntityCollectionException::invalidTrustAnchor(sprintf(
                'This endpoint only collects the entities under %s.',
                $this->trustAnchor,
            ));
        }

        $snapshots   = $this->collection->all();
        $lastUpdated = $this->settings->getInt(SettingsRepository::ENTITY_COLLECTION_REFRESHED_AT);
        $matches     = [];

        foreach ($this->activeSubordinates() as $subordinate) {
            // Registry changes (registration, status, edits) change the collection too.
            $lastUpdated = max($lastUpdated ?? 0, $subordinate->updatedAt ?? $subordinate->registeredAt);

            if ($request->from !== null && strcmp($subordinate->entityId, $request->from) < 0) {
                continue;
            }

            $entry = $this->entry($subordinate, $snapshots[$subordinate->entityId] ?? null, $now);
            if ($this->matches($entry, $request)) {
                $matches[] = $entry;
            }
        }

        $pageSize = min($request->limit ?? $this->maxPageSize, $this->maxPageSize);
        $page     = ['entities' => array_map(
            fn(array $entry): array => $this->present($entry, $request),
            array_slice($matches, 0, $pageSize),
        )];

        if (count($matches) > $pageSize) {
            // The pointer is the first entity of the next page; entities are ordered by entity_id,
            // so it stays valid when that entity leaves (the next page starts after it).
            $page['next'] = $matches[$pageSize]['entity_id'];
        }

        if ($lastUpdated !== null && $lastUpdated > 0) {
            $page['last_updated'] = $lastUpdated;
        }

        return $page;
    }


    /**
     * The informational claims of resolved metadata, per entity type (Entity Collection 1.0,
     * section 5.2): the OpenID Federation 1.0 section 5.2.2 claims, language-tagged variants
     * included, with display_name falling back to client_name / resource_name.
     *
     * @param array<array-key,mixed> $metadata Keyed by entity type.
     * @return array<string,array<string,mixed>>
     */
    public static function entityInfos(array $metadata): array
    {
        $infos = [];

        foreach ($metadata as $entityType => $claims) {
            if (!is_array($claims)) {
                continue;
            }

            $info = [];
            foreach ($claims as $name => $value) {
                if (in_array(self::baseName((string) $name), EntityCollectionRequest::INFO_CLAIMS, true)) {
                    $info[(string) $name] = $value;
                }
            }

            $fallback = match ((string) $entityType) {
                'openid_relying_party', 'oauth_client' => 'client_name',
                'oauth_resource'                       => 'resource_name',
                default                                => null,
            };
            $hasDisplayName = in_array('display_name', array_map(self::baseName(...), array_keys($info)), true);

            if ($fallback !== null && !$hasDisplayName) {
                foreach ($claims as $name => $value) {
                    if (self::baseName((string) $name) === $fallback) {
                        $info['display_name' . substr((string) $name, strlen($fallback))] = $value;
                    }
                }
            }

            if ($info !== []) {
                $infos[(string) $entityType] = $info;
            }
        }

        return $infos;
    }


    // -------------------------------------------------------------------------

    /**
     * Active subordinates in entity_id order, the order every page is cut from.
     *
     * @return list<\SimpleSAML\Module\oidanchor\Entity\Subordinate>
     */
    private function activeSubordinates(): array
    {
        $active = array_values(array_filter(
            $this->subordinates->findAll(),
            static fn(Subordinate $s): bool => $s->status === SubordinateStatus::Active->value,
        ));
        usort($active, static fn(Subordinate $a, Subordinate $b): int => strcmp($a->entityId, $b->entityId));

        return $active;
    }


    /**
     * @param Snapshot|null $snapshot
     * @return Entry
     */
    private function entry(Subordinate $subordinate, ?array $snapshot, int $now): array
    {
        $types = [...$subordinate->entityTypes, ...($snapshot['entity_types'] ?? [])];

        return [
            'entity_id'    => $subordinate->entityId,
            'entity_types' => array_values(array_unique($types)),
            'entity_infos' => $snapshot['entity_infos'] ?? [],
            // Verified at refresh time; one that has expired since no longer counts.
            'trust_marks'  => array_values(array_filter(
                $snapshot['trust_marks'] ?? [],
                static fn(array $mark): bool => (self::expiresAt($mark['trust_mark']) ?? PHP_INT_MAX) > $now,
            )),
        ];
    }


    /**
     * @param Entry $entry
     */
    private function matches(array $entry, EntityCollectionRequest $request): bool
    {
        // entity_type: any of the requested types.
        if ($request->entityTypes !== [] && array_intersect($entry['entity_types'], $request->entityTypes) === []) {
            return false;
        }

        // trust_mark_type: a verified Trust Mark of every requested type.
        $held = array_column($entry['trust_marks'], 'trust_mark_type');
        foreach ($request->trustMarkTypes as $type) {
            if (!in_array($type, $held, true)) {
                return false;
            }
        }

        return $request->query === null || $this->matchesQuery($entry, $request->query);
    }


    /**
     * Case-insensitive substring match against the entity_id and the names, descriptions and
     * keywords (in every language) the entity publishes.
     *
     * @param Entry $entry
     */
    private function matchesQuery(array $entry, string $query): bool
    {
        $haystack = [$entry['entity_id']];

        foreach ($entry['entity_infos'] as $info) {
            foreach ($info as $name => $value) {
                if (in_array(self::baseName((string) $name), self::SEARCHED_CLAIMS, true)) {
                    array_push($haystack, ...array_filter((array) $value, 'is_string'));
                }
            }
        }

        foreach ($haystack as $text) {
            if (mb_stripos($text, $query) !== false) {
                return true;
            }
        }

        return false;
    }


    /**
     * The Entity Info object as sent: only the requested claims, and only those this entity has.
     *
     * @param Entry $entry
     * @return array<string,mixed>
     */
    private function present(array $entry, EntityCollectionRequest $request): array
    {
        $out = ['entity_id' => $entry['entity_id']];

        if ($request->wantsEntityClaim('entity_types') && $entry['entity_types'] !== []) {
            $out['entity_types'] = $entry['entity_types'];
        }

        if ($request->wantsEntityClaim('entity_infos')) {
            $infos = [];
            foreach ($entry['entity_infos'] as $entityType => $info) {
                // With an entity_type filter, only the requested types are described.
                if ($request->entityTypes !== [] && !in_array($entityType, $request->entityTypes, true)) {
                    continue;
                }

                $info = array_filter($info, $request->wantsInfoClaim(...), ARRAY_FILTER_USE_KEY);
                if ($info !== []) {
                    $infos[$entityType] = $info;
                }
            }

            if ($infos !== []) {
                $out['entity_infos'] = $infos;
            }
        }

        if ($request->wantsEntityClaim('trust_marks') && $entry['trust_marks'] !== []) {
            $out['trust_marks'] = $entry['trust_marks'];
        }

        return $out;
    }


    /**
     * `display_name#de` => `display_name`.
     */
    private static function baseName(string $claim): string
    {
        return explode('#', $claim, 2)[0];
    }


    /**
     * The exp of a JWT that was verified when it was stored; only the timestamp is needed here.
     */
    private static function expiresAt(string $jwt): ?int
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);

        return is_array($payload) && is_numeric($payload['exp'] ?? null) ? (int) $payload['exp'] : null;
    }
}
