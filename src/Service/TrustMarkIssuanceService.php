<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use SimpleSAML\Module\oidanchor\Entity\IssuedTrustMark;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSpecRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * Issues Trust Marks driven by the spec/subject model: an issuance spec supplies the template
 * (lifetime, ref, logo, delegation, general claims, cache TTL) and a subject row grants
 * eligibility (status `active`) and may override the claims.
 *
 * The mark itself is built and signed through the library's TrustMarkFactory
 * (via FederationKeyService::signTrustMark), and persisted to the issued-marks log so the
 * public /trust_mark_status endpoint can answer for it.
 */
class TrustMarkIssuanceService
{
    public function __construct(
        private readonly FederationKeyService $keys,
        private readonly PDO $pdo,
    ) {
    }


    /**
     * Issue (or return a cached) Trust Mark for a subject of an issuance spec.
     *
     * @throws \RuntimeException When the spec is unknown.
     * @throws \InvalidArgumentException When the subject is not eligible.
     */
    public function issueForSubject(int $specId, int $subjectId): IssuedTrustMark
    {
        $specRepo = new TrustMarkSpecRepository($this->pdo);
        $spec     = $specRepo->findById($specId)
            ?? throw new RuntimeException(sprintf('Unknown issuance spec "%d".', $specId));

        $subjectRepo = new TrustMarkSubjectRepository($this->pdo);
        $subject     = $subjectRepo->findById($specId, $subjectId)
            ?? throw new RuntimeException(sprintf('Unknown subject "%d".', $subjectId));

        return $this->issue($spec, $subject);
    }


    /**
     * Issue a mark of a type to an entity directly (the admin UI's "issue" form): uses the type's
     * issuance spec, and registers the entity as an active subject of it when it is not one yet.
     *
     * @param ?int $lifetime Seconds from now; overrides the spec lifetime.
     * @param array<string,mixed> $extraClaims Per-issuance claims, merged over the spec/subject claims.
     * @throws \RuntimeException When no issuance spec exists for the type.
     * @throws \InvalidArgumentException When the entity is a subject that is not `active`.
     */
    public function issueForEntity(
        string $trustMarkType,
        string $sub,
        ?int $lifetime = null,
        array $extraClaims = [],
    ): IssuedTrustMark {
        $spec = (new TrustMarkSpecRepository($this->pdo))->findByType($trustMarkType)
            ?? throw new RuntimeException(sprintf('No issuance spec for Trust Mark type "%s".', $trustMarkType));

        $subjectRepo = new TrustMarkSubjectRepository($this->pdo);
        $subject     = $subjectRepo->findByTypeAndEntity($trustMarkType, $sub);
        if ($subject === null) {
            $id      = $subjectRepo->create((int) $spec['id'], $sub, 'active', null, null);
            $subject = $subjectRepo->findById((int) $spec['id'], $id)
                ?? throw new RuntimeException(sprintf('Could not register subject "%s".', $sub));
        }

        return $this->issue($spec, $subject, $lifetime, $extraClaims);
    }


    /**
     * The one place a Trust Mark is built, signed and recorded.
     *
     * Claims, later wins: the spec's descriptive claims (logo_uri, ref, delegation), then the
     * subject's additional_claims (which replace the spec's general claims entirely), then any
     * per-issuance $extraClaims, and finally the issuer-controlled claims (iss, sub, iat, exp,
     * trust_mark_type), which always win.
     *
     * @param array<string,mixed> $spec
     * @param array<string,mixed> $subject
     * @param ?int $lifetime Seconds from now; overrides the spec lifetime.
     * @param array<string,mixed> $extraClaims Per-issuance claims.
     * @throws \InvalidArgumentException When the subject's status is not `active`.
     */
    public function issue(array $spec, array $subject, ?int $lifetime = null, array $extraClaims = []): IssuedTrustMark
    {
        if (($subject['status'] ?? '') !== 'active') {
            throw new InvalidArgumentException(sprintf(
                'Subject "%s" is not eligible (status: %s).',
                (string) $subject['entity_id'],
                (string) ($subject['status'] ?? 'unknown'),
            ));
        }

        $trustMarkType = (string) $spec['trust_mark_type'];
        $sub           = (string) $subject['entity_id'];
        $issuedRepo    = new IssuedTrustMarkRepository($this->pdo);
        $now           = time();

        // cache_ttl: reuse the most recent active mark while it is fresh enough — unless this
        // issuance asks for something specific.
        $cacheTtl = (int) ($spec['cache_ttl'] ?? 0);
        if ($cacheTtl > 0 && $lifetime === null && $extraClaims === []) {
            $existing = $issuedRepo->findActive($trustMarkType, $sub);
            if (
                $existing !== null
                && $existing->iat + $cacheTtl > $now
                && ($existing->exp === null || $existing->exp > $now)
            ) {
                return $existing;
            }
        }

        $lifetime ??= isset($spec['lifetime']) ? (int) $spec['lifetime'] : null;
        $exp        = $lifetime !== null && $lifetime > 0 ? $now + $lifetime : null;

        // Per the spec: a subject's additional_claims replace the spec's general claims entirely.
        $additionalClaims = array_key_exists('additional_claims', $subject) && is_array($subject['additional_claims'])
            ? $subject['additional_claims']
            : (is_array($spec['additional_claims'] ?? null) ? $spec['additional_claims'] : []);

        $payload = [];
        if (isset($spec['logo_uri'])) {
            $payload[ClaimsEnum::LogoUri->value] = (string) $spec['logo_uri'];
        }
        if (isset($spec['ref'])) {
            $payload[ClaimsEnum::Ref->value] = (string) $spec['ref'];
        }
        if (isset($spec['delegation_jwt'])) {
            $payload[ClaimsEnum::Delegation->value] = (string) $spec['delegation_jwt'];
        }

        $payload = array_merge($payload, $additionalClaims, $extraClaims);

        // Issuer-controlled claims always win.
        $payload[ClaimsEnum::Iss->value]           = $this->keys->entityId();
        $payload[ClaimsEnum::Sub->value]           = $sub;
        $payload[ClaimsEnum::Iat->value]           = $now;
        $payload[ClaimsEnum::TrustMarkType->value] = $trustMarkType;

        if ($exp !== null) {
            $payload[ClaimsEnum::Exp->value] = $exp;
        }

        $jwt = $this->keys->signTrustMark($payload);

        $mark = new IssuedTrustMark(
            id:               null,
            trustMarkType:    $trustMarkType,
            sub:              $sub,
            jwt:              $jwt,
            iat:              $now,
            exp:              $exp,
            status:           'active',
            revokedAt:        null,
            revocationReason: null,
        );

        $id = $issuedRepo->create($mark);

        return new IssuedTrustMark(
            id:               $id,
            trustMarkType:    $mark->trustMarkType,
            sub:              $mark->sub,
            jwt:              $mark->jwt,
            iat:              $mark->iat,
            exp:              $mark->exp,
            status:           $mark->status,
            revokedAt:        $mark->revokedAt,
            revocationReason: $mark->revocationReason,
        );
    }


    /**
     * Revoke every active mark of a type held by a subject — used when a subject's status
     * leaves `active`, so /trust_mark_status stops reporting the mark as valid.
     */
    public function revokeMarksForSubject(string $trustMarkType, string $sub, string $reason): void
    {
        $issuedRepo = new IssuedTrustMarkRepository($this->pdo);

        foreach ($issuedRepo->findAll($trustMarkType, $sub, 'active') as $mark) {
            if ($mark->id !== null) {
                $issuedRepo->revoke($mark->id, $reason);
            }
        }
    }
}
