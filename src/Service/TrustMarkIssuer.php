<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use RuntimeException;
use SimpleSAML\Module\oidanchor\Entity\IssuedTrustMark;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * Issues Trust Marks: builds the payload from a catalog type, signs it with the TA's
 * federation key via {@see FederationKeyService}, and persists the result.
 */
class TrustMarkIssuer
{
    public function __construct(
        private readonly FederationKeyService $keys,
        private readonly TrustMarkTypeRepository $typeRepository,
        private readonly IssuedTrustMarkRepository $issuedRepository,
    ) {
    }


    /**
     * Issue a Trust Mark of the given type for the given subject.
     *
     * @param string $trustMarkType The Trust Mark Type identifier (must exist in the catalog).
     * @param string $sub The entity the mark is issued for.
     * @param ?int $exp Absolute expiration timestamp. When null, the type's default_lifetime
     *                  is applied as a duration from now; if that is also null, the mark has no exp.
     * @param array<string,mixed> $extraClaims Per-issuance claims merged on top of the type's extra_claims.
     *
     * @throws RuntimeException When the type does not exist.
     */
    public function issue(string $trustMarkType, string $sub, ?int $exp = null, array $extraClaims = []): IssuedTrustMark
    {
        $type = $this->typeRepository->findById($trustMarkType)
            ?? throw new RuntimeException(sprintf('Unknown Trust Mark type "%s".', $trustMarkType));

        $now = time();

        // Explicit absolute exp wins; otherwise apply the type default_lifetime as a duration; otherwise no exp.
        if ($exp === null && $type->defaultLifetime !== null) {
            $exp = $now + $type->defaultLifetime;
        }

        // Build the payload: descriptive claims first, then type extra_claims, then per-issuance
        // extra_claims (later wins on conflict), and finally the issuer-controlled claims (always win).
        $payload = [];

        if ($type->logoUri !== null) {
            $payload[ClaimsEnum::LogoUri->value] = $type->logoUri;
        }
        if ($type->refUri !== null) {
            $payload[ClaimsEnum::Ref->value] = $type->refUri;
        }
        if ($type->extraClaims !== null) {
            $payload = array_merge($payload, $type->extraClaims);
        }
        if ($extraClaims !== []) {
            $payload = array_merge($payload, $extraClaims);
        }

        $payload[ClaimsEnum::Iss->value]           = $this->keys->entityId();
        $payload[ClaimsEnum::Sub->value]           = $sub;
        $payload[ClaimsEnum::Iat->value]           = $now;
        $payload[ClaimsEnum::TrustMarkType->value] = $type->trustMarkId;

        if ($exp !== null) {
            $payload[ClaimsEnum::Exp->value] = $exp;
        }

        $jwt = $this->keys->signTrustMark($payload);

        $mark = new IssuedTrustMark(
            id:               null,
            trustMarkId:      $type->trustMarkId,
            sub:              $sub,
            jwt:              $jwt,
            iat:              $now,
            exp:              $exp,
            status:           'active',
            revokedAt:        null,
            revocationReason: null,
        );

        $id = $this->issuedRepository->create($mark);

        return new IssuedTrustMark(
            id:               $id,
            trustMarkId:      $mark->trustMarkId,
            sub:              $mark->sub,
            jwt:              $mark->jwt,
            iat:              $mark->iat,
            exp:              $mark->exp,
            status:           $mark->status,
            revokedAt:        $mark->revokedAt,
            revocationReason: $mark->revocationReason,
        );
    }
}
