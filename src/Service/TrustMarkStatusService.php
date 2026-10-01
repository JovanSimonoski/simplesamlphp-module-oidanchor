<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

/**
 * Answers Trust Mark status queries against the TA's issued-marks registry.
 *
 * The persisted registry is authoritative for the status decision. When the caller supplies
 * the full Trust Mark JWT, the library is used to parse it and recover the lookup keys
 * (trust_mark_type, sub) and confirm this TA is the issuer.
 *
 * Since the issuance-spec model landed, a subject row may also withdraw eligibility: a mark
 * whose subject is no longer `active` reports as revoked even if its issued row still says
 * active (the two are kept in step by TrustMarkIssuanceService, this is the safety net).
 */
class TrustMarkStatusService
{
    private ?Federation $federation = null;


    public function __construct(
        private readonly FederationKeyService $keys,
        private readonly IssuedTrustMarkRepository $issuedRepository,
        private readonly ?TrustMarkSubjectRepository $subjectRepository = null,
    ) {
    }


    /**
     * Resolve the status of a Trust Mark.
     *
     * Provide either (trust_mark_type + sub) or the full jwt. When jwt is supplied its claims
     * take precedence over any conflicting trust_mark_type/sub arguments (the JWT is authoritative
     * for what is being asked about).
     *
     * @return array{
     *     status: string,
     *     active: bool,
     *     trust_mark_type: ?string,
     *     sub: ?string,
     *     iat: ?int,
     *     exp: ?int,
     *     revoked_at: ?int,
     *     reason: ?string,
     *     trust_mark: ?string,
     *     message: ?string
     * }
     */
    public function getStatus(?string $trustMarkType, ?string $sub, ?string $jwt = null): array
    {
        $providedJwt = null;

        if ($jwt !== null && $jwt !== '') {
            $claims = $this->extractMarkClaims($jwt);

            if ($claims === null) {
                return $this->result(
                    TrustMarkStatusEnum::Invalid,
                    $trustMarkType,
                    $sub,
                    trustMark: $jwt,
                    message: 'Could not parse the supplied Trust Mark.',
                );
            }

            if ($claims['iss'] !== $this->keys->entityId()) {
                return $this->result(
                    TrustMarkStatusEnum::Invalid,
                    $claims['trust_mark_type'],
                    $claims['sub'],
                    trustMark: $jwt,
                    message: 'Trust Mark was not issued by this Trust Anchor.',
                );
            }

            $trustMarkType = $claims['trust_mark_type'];
            $sub           = $claims['sub'];
            $providedJwt   = $jwt;
        }

        if ($trustMarkType === null || $trustMarkType === '' || $sub === null || $sub === '') {
            return $this->result(
                TrustMarkStatusEnum::Invalid,
                $trustMarkType,
                $sub,
                trustMark: $providedJwt,
                message: 'trust_mark_type and sub are required.',
            );
        }

        $row = $this->issuedRepository->findLatest($trustMarkType, $sub);

        if ($row === null) {
            return $this->result(
                TrustMarkStatusEnum::Invalid,
                $trustMarkType,
                $sub,
                trustMark: $providedJwt,
                message: 'No such Trust Mark has been issued by this Trust Anchor.',
            );
        }

        if ($row->status === 'revoked') {
            return $this->result(
                TrustMarkStatusEnum::Revoked,
                $trustMarkType,
                $sub,
                iat: $row->iat,
                exp: $row->exp,
                revokedAt: $row->revokedAt,
                reason: $row->revocationReason,
                trustMark: $providedJwt ?? $row->jwt,
            );
        }

        if ($row->exp !== null && $row->exp <= time()) {
            return $this->result(
                TrustMarkStatusEnum::Expired,
                $trustMarkType,
                $sub,
                iat: $row->iat,
                exp: $row->exp,
                trustMark: $providedJwt ?? $row->jwt,
            );
        }

        // The issuance-spec subject withdraws eligibility independently of the issued row.
        $subject = $this->subjectRepository?->findByTypeAndEntity($trustMarkType, $sub);
        if ($subject !== null && $subject['status'] !== 'active') {
            return $this->result(
                TrustMarkStatusEnum::Revoked,
                $trustMarkType,
                $sub,
                iat: $row->iat,
                exp: $row->exp,
                reason: sprintf('subject status is "%s"', (string) $subject['status']),
                trustMark: $providedJwt ?? $row->jwt,
            );
        }

        return $this->result(
            TrustMarkStatusEnum::Active,
            $trustMarkType,
            $sub,
            iat: $row->iat,
            exp: $row->exp,
            trustMark: $providedJwt ?? $row->jwt,
        );
    }


    /**
     * @return array{iss: string, sub: string, trust_mark_type: string}|null
     */
    private function extractMarkClaims(string $jwt): ?array
    {
        // Strict library parse first — validates structure and timestamps.
        try {
            $mark = $this->federation()->trustMarkFactory()->fromToken($jwt);

            return [
                'iss'             => $mark->getIssuer(),
                'sub'             => $mark->getSubject(),
                'trust_mark_type' => $mark->getTrustMarkType(),
            ];
        } catch (Throwable) {
            // Strict parsing rejects legitimately expired marks. Fall back to a lenient,
            // signature-agnostic read of the payload purely to recover the lookup keys; the
            // persisted registry remains authoritative for the actual status decision below.
            return $this->lenientPayloadLookup($jwt);
        }
    }


    /**
     * @return array{iss: string, sub: string, trust_mark_type: string}|null
     */
    private function lenientPayloadLookup(string $jwt): ?array
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
        if (!is_array($payload)) {
            return null;
        }

        $iss  = $payload['iss'] ?? null;
        $sub  = $payload['sub'] ?? null;
        $type = $payload['trust_mark_type'] ?? ($payload['id'] ?? null);

        if (!is_string($iss) || !is_string($sub) || !is_string($type)) {
            return null;
        }

        return ['iss' => $iss, 'sub' => $sub, 'trust_mark_type' => $type];
    }


    /**
     * @return array{
     *     status: string, active: bool, trust_mark_type: ?string, sub: ?string,
     *     iat: ?int, exp: ?int, revoked_at: ?int, reason: ?string, trust_mark: ?string, message: ?string
     * }
     */
    private function result(
        TrustMarkStatusEnum $status,
        ?string $trustMarkType,
        ?string $sub,
        ?int $iat = null,
        ?int $exp = null,
        ?int $revokedAt = null,
        ?string $reason = null,
        ?string $trustMark = null,
        ?string $message = null,
    ): array {
        return [
            'status'          => $status->value,
            'active'          => $status->isValid(),
            'trust_mark_type' => $trustMarkType,
            'sub'             => $sub,
            'iat'             => $iat,
            'exp'             => $exp,
            'revoked_at'      => $revokedAt,
            'reason'          => $reason,
            'trust_mark'      => $trustMark,
            'message'         => $message,
        ];
    }


    private function federation(): Federation
    {
        return $this->federation ??= new Federation(
            new SupportedAlgorithms(new SignatureAlgorithmBag($this->keys->algorithm())),
        );
    }
}
