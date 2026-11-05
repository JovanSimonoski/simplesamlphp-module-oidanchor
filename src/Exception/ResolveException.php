<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Exception;

use RuntimeException;
use Throwable;

/**
 * Thrown by the resolver when a resolution cannot complete. Carries the OpenID Federation
 * error code and the HTTP status the controller should return.
 */
class ResolveException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $httpStatus = 400,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }


    public static function invalidTrustAnchor(string $message): self
    {
        return new self('invalid_trust_anchor', $message, 400);
    }


    public static function notFound(string $message): self
    {
        return new self('not_found', $message, 404);
    }


    public static function invalidTrustChain(string $message, ?Throwable $previous = null): self
    {
        return new self('invalid_trust_chain', $message, 400, $previous);
    }


    public static function invalidRequest(string $message): self
    {
        return new self('invalid_request', $message, 400);
    }


    public static function unsupportedParameter(string $message): self
    {
        return new self('unsupported_parameter', $message, 400);
    }
}
