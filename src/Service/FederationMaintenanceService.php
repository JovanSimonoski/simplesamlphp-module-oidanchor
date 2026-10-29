<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;

/**
 * Periodic work that must stay off the public request path: interval-based signing-key
 * rotation and the refresh / re-issuance of the TA's own Entity Configuration Trust Marks.
 *
 * Run by {@see \SimpleSAML\Module\oidanchor\Event\Listener\CronListener}.
 */
class FederationMaintenanceService
{
    public function __construct(
        private readonly Configuration $moduleConfig,
        private readonly FederationKeyService $keys,
    ) {
    }


    /**
     * @return list<string> Human-readable summary lines.
     */
    public function run(): array
    {
        $summary = [];

        // Rotate first, so self-issued marks re-signed below use the new key.
        $rotated = $this->keys->keyManagement()->rotateIfDue();
        if ($rotated !== null) {
            $summary[] = sprintf('signing key rotated to %s', $rotated->kid);
        }

        $counts = (new EcTrustMarkService(
            $this->keys,
            new EcTrustMarkRepository($this->keys->pdoConnection()),
            $this->moduleConfig,
        ))->refreshAll(reissueSelfIssued: $rotated !== null);

        $summary[] = sprintf(
            'entity configuration trust marks: %d refreshed, %d failed',
            $counts['refreshed'],
            $counts['failed'],
        );

        return $summary;
    }
}
