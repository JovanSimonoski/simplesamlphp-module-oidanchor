<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

/**
 * Trust Mark delegation (OpenID Federation 1.0 §7.5): a JWT signed by the Trust Mark *owner*
 * that authorises an issuer to issue marks of that type. The issuer embeds it as the
 * `delegation` claim of each mark it issues.
 *
 * Building and parsing both go through the library's TrustMarkDelegationFactory, which sets
 * the `trust-mark-delegation+jwt` typ header and validates the required claims.
 */
class TrustMarkDelegationService
{
    /** Default delegation validity when the TA mints one for itself. */
    private const DEFAULT_LIFETIME = 31536000;

    private ?Federation $federation = null;

    private ?FederationKeyService $keys = null;


    public function __construct(
        private readonly Configuration $moduleConfig,
        private readonly PDO $pdo,
    ) {
    }


    /**
     * Mint a delegation JWT when this TA is the owner of the type — the only case in which we
     * hold the owner's signing key. Returns null when the owner is some other entity (its
     * delegation must then be supplied through the issuance spec's delegation_jwt).
     */
    public function mintIfOwnedByThisAnchor(string $trustMarkType, string $ownerEntityId): ?string
    {
        $keys = $this->keys();
        if ($ownerEntityId !== $keys->entityId()) {
            return null;
        }

        return $this->mint($trustMarkType, $keys->entityId());
    }


    /**
     * Mint a delegation JWT: this TA (as owner) authorises $issuer to issue $trustMarkType.
     */
    public function mint(string $trustMarkType, string $issuer, ?int $lifetime = null): string
    {
        $keys = $this->keys();
        $now  = time();

        return $keys->signTrustMarkDelegation([
            ClaimsEnum::Iss->value           => $keys->entityId(),
            ClaimsEnum::Sub->value           => $issuer,
            ClaimsEnum::Iat->value           => $now,
            ClaimsEnum::Exp->value           => $now + ($lifetime ?? self::DEFAULT_LIFETIME),
            ClaimsEnum::TrustMarkType->value => $trustMarkType,
        ]);
    }


    /**
     * Parse a supplied delegation JWT and check it authorises $issuer for $trustMarkType.
     *
     * @return array{iss: string, sub: string, trust_mark_type: string}
     * @throws InvalidArgumentException When the JWT cannot be parsed or does not match.
     */
    public function validate(string $delegationJwt, string $trustMarkType, string $issuer): array
    {
        try {
            $delegation = $this->federation()->trustMarkDelegationFactory()->fromToken($delegationJwt);

            $claims = [
                'iss'             => $delegation->getIssuer(),
                'sub'             => $delegation->getSubject(),
                'trust_mark_type' => $delegation->getTrustMarkType(),
            ];
        } catch (Throwable $e) {
            throw new InvalidArgumentException('Invalid delegation JWT: ' . $e->getMessage(), 0, $e);
        }

        if ($claims['trust_mark_type'] !== $trustMarkType) {
            throw new InvalidArgumentException(sprintf(
                'Delegation JWT is for trust mark type "%s", not "%s".',
                $claims['trust_mark_type'],
                $trustMarkType,
            ));
        }

        if ($claims['sub'] !== $issuer) {
            throw new InvalidArgumentException(sprintf(
                'Delegation JWT authorises issuer "%s", not "%s".',
                $claims['sub'],
                $issuer,
            ));
        }

        return $claims;
    }


    private function keys(): FederationKeyService
    {
        return $this->keys ??= new FederationKeyService($this->moduleConfig, $this->pdo);
    }


    private function federation(): Federation
    {
        return $this->federation ??= new Federation(
            new SupportedAlgorithms(new SignatureAlgorithmBag($this->keys()->algorithm())),
        );
    }
}
