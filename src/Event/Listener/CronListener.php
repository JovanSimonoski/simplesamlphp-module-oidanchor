<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Event\Listener;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\cron\Event\CronEvent;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\FederationMaintenanceService;
use Throwable;

/**
 * Runs the module's periodic maintenance (key rotation, EC trust mark refresh) from the
 * SimpleSAMLphp cron module, on the tag configured as `cron_tag` (default: hourly).
 */
class CronListener
{
    public function onCron(CronEvent $event): void
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        if ($event->getTag() !== $moduleConfig->getOptionalString('cron_tag', 'hourly')) {
            return;
        }

        try {
            $summary = (new FederationMaintenanceService($moduleConfig, new FederationKeyService($moduleConfig)))->run();
            $event->addResult('oidanchor', true, 'oidanchor: ' . implode('; ', $summary));
        } catch (Throwable $e) {
            Logger::error('oidanchor: cron maintenance failed: ' . $e->getMessage());
            $event->addResult('oidanchor', false, 'oidanchor: maintenance failed: ' . $e->getMessage());
        }
    }
}
