<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Exception;

use RuntimeException;

/**
 * A request to the Entity Collection endpoint that cannot be answered. Carries the error code and
 * HTTP status defined by OpenID Federation Entity Collection 1.0 for the condition.
 */
class EntityCollectionException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $httpStatus = 400,
    ) {
        parent::__construct($message);
    }


    public static function invalidRequest(string $message): self
    {
        return new self('invalid_request', $message, 400);
    }


    public static function unsupportedClaim(string $message): self
    {
        return new self('unsupported_claim', $message, 400);
    }


    public static function invalidTrustAnchor(string $message): self
    {
        return new self('invalid_trust_anchor', $message, 404);
    }
}
