<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Event\Listener;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\cron\Event\CronEvent;
use SimpleSAML\Module\oidanchor\Event\Listener\CronListener;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(CronListener::class)]
final class CronListenerTest extends TestCase
{
    public function testRunsMaintenanceOnTheConfiguredTag(): void
    {
        $this->preloadModuleConfig(['cron_tag' => 'daily']);
        $event = new CronEvent('daily');

        (new CronListener())->onCron($event);

        $this->assertFalse($event->hasFailures());
        $this->assertArrayHasKey('oidanchor', $event->getResults());
        $this->assertStringContainsString('entity configuration trust marks', $event->getResults()['oidanchor']['message']);
    }


    public function testIgnoresOtherTags(): void
    {
        $this->preloadModuleConfig();
        $event = new CronEvent('daily');

        (new CronListener())->onCron($event);

        $this->assertSame([], $event->getResults());
    }
}
