<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Claims\TrustMarksClaimValue;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

/**
 * Materialises the TA's own trust marks (Entity Configuration Trust Marks) into the
 * `trust_marks` claim of the entity configuration.
 *
 * Three variants per the spec: a directly supplied JWT, an externally fetched mark
 * (type + issuer, refreshed via the library's TrustMarkFetcher against the issuer's
 * federation_trust_mark_endpoint), and a self-issued mark (signed here with the TA key
 * via the library's TrustMarkFactory; always refreshed based on its configured lifetime).
 */
class EcTrustMarkService
{
    private const DEFAULT_SELF_ISSUED_LIFETIME = 86400;

    private ?Federation $federation = null;


    public function __construct(
        private readonly FederationKeyService $keys,
        private readonly EcTrustMarkRepository $repository,
    ) {
    }


    /**
     * Build the `trust_marks` claim entries. Rows without a usable JWT are skipped.
     *
     * @return list<array<string,mixed>>
     */
    public function claimValues(): array
    {
        $entries = [];

        foreach ($this->repository->findAll() as $row) {
            try {
                $jwt = $this->materialize($row);
            } catch (Throwable $e) {
                Logger::warning(sprintf(
                    'oidanchor: could not materialise EC trust mark #%d: %s',
                    $row['id'],
                    $e->getMessage(),
                ));
                continue;
            }

            $type = $row['trust_mark_type'];
            if ($jwt === null || $type === null) {
                continue;
            }

            $entries[] = (new TrustMarksClaimValue($type, $jwt))->jsonSerialize();
        }

        return $entries;
    }


    /**
     * Resolve the current JWT for a stored row, refreshing / self-issuing when due.
     *
     * @param array<string,mixed> $row
     */
    public function materialize(array $row): ?string
    {
        if (is_array($row['self_issuance_spec'])) {
            return $this->selfIssued($row);
        }

        $jwt = $row['trust_mark'];
        $exp = $jwt !== null ? $this->expOf($jwt) : null;
        $now = time();

        $minLifetime = $row['min_lifetime'] ?? 0;
        $grace       = $row['refresh_grace_period'] ?? 0;

        $isStale = $jwt === null
            || ($exp !== null && $exp - $now < $minLifetime);

        if ($row['refresh'] && $isStale && $this->refreshAllowed($row, $now)) {
            $fresh = $this->fetchExternal($row);
            if ($fresh !== null) {
                $this->repository->update($row['id'], ['trust_mark' => $fresh, 'last_refresh_at' => $now]);

                return $fresh;
            }
        }

        // Never embed a mark that is past its exp and beyond the refresh grace window.
        if ($jwt !== null && $exp !== null && $exp + $grace <= $now && $exp <= $now) {
            return null;
        }

        return $jwt;
    }


    // -------------------------------------------------------------------------

    /**
     * @param array<string,mixed> $row
     */
    private function selfIssued(array $row): ?string
    {
        $spec     = (array) $row['self_issuance_spec'];
        $lifetime = is_int($spec['lifetime'] ?? null) && $spec['lifetime'] > 0
            ? $spec['lifetime']
            : self::DEFAULT_SELF_ISSUED_LIFETIME;

        $now         = time();
        $lastRefresh = $row['last_refresh_at'] ?? 0;

        // Re-issue halfway through the lifetime so the published mark never goes stale.
        if ($row['trust_mark'] !== null && $lastRefresh + intdiv($lifetime, 2) > $now) {
            return $row['trust_mark'];
        }

        $type     = $row['trust_mark_type'];
        $entityId = $this->keys->entityId();
        if ($type === null) {
            return null;
        }

        $payload = [];
        if (isset($spec['logo_uri']) && is_string($spec['logo_uri'])) {
            $payload[ClaimsEnum::LogoUri->value] = $spec['logo_uri'];
        }
        if (isset($spec['ref']) && is_string($spec['ref'])) {
            $payload[ClaimsEnum::Ref->value] = $spec['ref'];
        }
        if (isset($spec['additional_claims']) && is_array($spec['additional_claims'])) {
            $payload = array_merge($payload, $spec['additional_claims']);
        }

        $payload[ClaimsEnum::Iss->value]           = $entityId;
        $payload[ClaimsEnum::Sub->value]           = $entityId;
        $payload[ClaimsEnum::Iat->value]           = $now;
        $payload[ClaimsEnum::Exp->value]           = $now + $lifetime;
        $payload[ClaimsEnum::TrustMarkType->value] = $type;

        $jwt = $this->keys->signTrustMark($payload);
        $this->repository->update($row['id'], ['trust_mark' => $jwt, 'last_refresh_at' => $now]);

        return $jwt;
    }


    /**
     * @param array<string,mixed> $row
     */
    private function refreshAllowed(array $row, int $now): bool
    {
        $rateLimit   = $row['refresh_rate_limit'] ?? 0;
        $lastRefresh = $row['last_refresh_at'] ?? 0;

        return $rateLimit < 1 || $lastRefresh + $rateLimit <= $now;
    }


    /**
     * Fetch a fresh mark from the issuer's federation_trust_mark_endpoint via the library.
     *
     * @param array<string,mixed> $row
     */
    private function fetchExternal(array $row): ?string
    {
        $type   = $row['trust_mark_type'];
        $issuer = $row['trust_mark_issuer'];
        if ($type === null || $issuer === null) {
            return null;
        }

        try {
            $federation = $this->federation();
            $issuerConfiguration = $federation->entityStatementFetcher()
                ->fromCacheOrWellKnownEndpoint($issuer);

            return $federation->trustMarkFetcher()
                ->fromCacheOrFederationTrustMarkEndpoint($type, $this->keys->entityId(), $issuerConfiguration)
                ->getToken();
        } catch (Throwable $e) {
            Logger::warning(sprintf(
                'oidanchor: EC trust mark refresh failed for "%s" from "%s": %s',
                $type,
                $issuer,
                $e->getMessage(),
            ));

            return null;
        }
    }


    /**
     * Lenient exp read: the mark may be signed by a remote issuer whose keys we do not
     * hold, so a full library parse is not always possible; only the timestamp is needed.
     */
    private function expOf(string $jwt): ?int
    {
        $parts = explode('.', $jwt);
        if (count($parts) < 2) {
            return null;
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        $payload = json_decode($decoded, true);

        return is_array($payload) && isset($payload['exp']) && is_numeric($payload['exp'])
            ? (int) $payload['exp']
            : null;
    }


    private function federation(): Federation
    {
        return $this->federation ??= new Federation(
            new SupportedAlgorithms(new SignatureAlgorithmBag($this->keys->algorithm())),
        );
    }
}
