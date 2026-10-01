<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\OpenID\Federation\TrustChain;

/**
 * Outcome of a successful resolution.
 *
 * Holds the verified trust chain, the policy-applied metadata (by entity type), the validated
 * Trust Marks (as { trust_mark_type, trust_mark } entries) and any non-fatal warnings.
 */
class ResolveResult
{
    /**
     * @param string $sub Resolved entity.
     * @param TrustChain $trustChain The verified trust chain (leaf → trust anchor).
     * @param list<string> $trustChainTokens Compact JWS strings of the chain, leaf-first.
     * @param array<string,array<string,mixed>> $metadata Policy-applied metadata, keyed by entity type.
     * @param list<array{trust_mark_type:string,trust_mark:string}> $trustMarks Validated Trust Marks.
     * @param list<string> $warnings Non-fatal warnings collected during resolution.
     * @param int $expiration Trust chain expiration (unix time).
     */
    public function __construct(
        public readonly string $sub,
        public readonly TrustChain $trustChain,
        public readonly array $trustChainTokens,
        public readonly array $metadata,
        public readonly array $trustMarks,
        public readonly array $warnings,
        public readonly int $expiration,
    ) {
    }
}
