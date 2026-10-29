<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Claims\TrustMarksClaimValue;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

/**
 * The TA's own trust marks (Entity Configuration Trust Marks) and the `trust_marks` claim.
 *
 * Three variants per the spec: a directly supplied JWT, an externally fetched mark
 * (type + issuer, refreshed via the library's TrustMarkFetcher against the issuer's
 * federation_trust_mark_endpoint), and a self-issued mark (signed here with the TA key).
 *
 * Reading and refreshing are deliberately separate. {@see claimValues()} runs on the public
 * Entity Configuration request and only serves what is stored — no outbound HTTP, no signing,
 * no writes. Fetching and self-issuance happen in {@see refresh()} / {@see refreshAll()}, which
 * run from the cron listener and when an admin edits a mark.
 */
class EcTrustMarkService
{
    private const int DEFAULT_SELF_ISSUED_LIFETIME = 86400;


    private ?Federation $federation = null;


    public function __construct(
        private readonly FederationKeyService $keys,
        private readonly EcTrustMarkRepository $repository,
        private readonly ?Configuration $moduleConfig = null,
    ) {
    }


    /**
     * Build the `trust_marks` claim entries from the stored marks. Rows without a usable JWT
     * (missing, or expired beyond the refresh grace period) are skipped.
     *
     * @return list<array<string,mixed>>
     */
    public function claimValues(): array
    {
        $entries = [];
        $now     = time();

        foreach ($this->repository->findAll() as $row) {
            $jwt  = $this->current($row, $now);
            $type = $row['trust_mark_type'];

            if ($jwt === null || $type === null) {
                continue;
            }

            $entries[] = (new TrustMarksClaimValue($type, $jwt))->jsonSerialize();
        }

        return $entries;
    }


    /**
     * Refresh every stored mark that is due.
     *
     * @param bool $reissueSelfIssued Re-sign self-issued marks even when not due (after a key rotation).
     * @return array{refreshed: int, failed: int}
     */
    public function refreshAll(bool $reissueSelfIssued = false): array
    {
        $counts = ['refreshed' => 0, 'failed' => 0];

        foreach ($this->repository->findAll() as $row) {
            $result = $this->refresh($row, $reissueSelfIssued && is_array($row['self_issuance_spec']));
            if ($result !== null) {
                $counts[$result ? 'refreshed' : 'failed']++;
            }
        }

        return $counts;
    }


    /**
     * Refresh one stored mark when it is due (or when forced): re-sign a self-issued mark, or
     * fetch an external one from its issuer. Every attempt is recorded in last_refresh_at, so
     * refresh_rate_limit also throttles retries against an issuer that keeps failing.
     *
     * @param array<string,mixed> $row
     * @return bool|null True when a new JWT was stored, false when an attempt failed, null when not due.
     */
    public function refresh(array $row, bool $force = false): ?bool
    {
        $now = time();

        if (is_array($row['self_issuance_spec'])) {
            if (!$force && !$this->selfIssuedDue($row, $now)) {
                return null;
            }

            try {
                $jwt = $this->selfIssue($row, $now);
            } catch (Throwable $e) {
                Logger::warning(sprintf('oidanchor: could not self-issue EC trust mark #%d: %s', $row['id'], $e->getMessage()));
                $jwt = null;
            }
        } else {
            if (!$row['refresh'] || !$this->externalDue($row, $now) || !$this->refreshAllowed($row, $now)) {
                return null;
            }

            $jwt = $this->fetchExternal($row);
        }

        $this->repository->update($row['id'], $jwt !== null
            ? ['trust_mark' => $jwt, 'last_refresh_at' => $now]
            : ['last_refresh_at' => $now]);

        return $jwt !== null;
    }


    // -------------------------------------------------------------------------

    /**
     * The stored JWT, unless it is past its exp and beyond the refresh grace window.
     *
     * @param array<string,mixed> $row
     */
    private function current(array $row, int $now): ?string
    {
        $jwt = $row['trust_mark'];
        if ($jwt === null) {
            return null;
        }

        $exp   = $this->expOf($jwt);
        $grace = $row['refresh_grace_period'] ?? 0;

        return $exp !== null && $exp + $grace <= $now ? null : $jwt;
    }


    /**
     * Self-issued marks are re-issued halfway through their lifetime so the published mark never goes stale.
     *
     * @param array<string,mixed> $row
     */
    private function selfIssuedDue(array $row, int $now): bool
    {
        $lastRefresh = $row['last_refresh_at'] ?? 0;

        return $row['trust_mark'] === null
            || $lastRefresh + intdiv($this->selfIssuedLifetime($row), 2) <= $now;
    }


    /**
     * @param array<string,mixed> $row
     */
    private function externalDue(array $row, int $now): bool
    {
        $jwt = $row['trust_mark'];
        if ($jwt === null) {
            return true;
        }

        $exp = $this->expOf($jwt);

        return $exp !== null && $exp - $now < ($row['min_lifetime'] ?? 0);
    }


    /**
     * @param array<string,mixed> $row
     */
    private function selfIssuedLifetime(array $row): int
    {
        $spec = (array) $row['self_issuance_spec'];

        return is_int($spec['lifetime'] ?? null) && $spec['lifetime'] > 0
            ? $spec['lifetime']
            : self::DEFAULT_SELF_ISSUED_LIFETIME;
    }


    /**
     * @param array<string,mixed> $row
     */
    private function selfIssue(array $row, int $now): ?string
    {
        $spec     = (array) $row['self_issuance_spec'];
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
        $payload[ClaimsEnum::Exp->value]           = $now + $this->selfIssuedLifetime($row);
        $payload[ClaimsEnum::TrustMarkType->value] = $type;

        return $this->keys->signTrustMark($payload);
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
            supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag($this->keys->algorithm())),
            client: FederationHttpClient::create(
                $this->moduleConfig ?? Configuration::loadFromArray([]),
                'oidanchor-trust-mark-refresh/1.0 (+' . $this->keys->entityId() . ')',
            ),
        );
    }
}
