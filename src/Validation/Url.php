<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

/**
 * URL checks shared by the validators and controllers.
 */
final class Url
{
    /**
     * Whether $url is an absolute https URL with a host (entity identifiers, trust mark types).
     */
    public static function isHttps(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
