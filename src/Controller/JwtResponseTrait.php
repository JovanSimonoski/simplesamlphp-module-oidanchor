<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use Symfony\Component\HttpFoundation\Response;

/**
 * Builds a 200 response for a freshly signed federation JWT, with Cache-Control derived from the
 * token's own `exp` claim so federation clients and intermediaries can cache it until it expires.
 */
trait JwtResponseTrait
{
    private function jwtResponse(string $token, string $contentType): Response
    {
        $response = new Response($token, Response::HTTP_OK, ['Content-Type' => $contentType]);

        $exp = $this->jwtExpiration($token);
        if ($exp !== null) {
            $response->setPublic();
            $response->setMaxAge(max(0, $exp - time()));
        }

        return $response;
    }


    /**
     * Read `exp` from a JWT we just signed ourselves (no verification needed).
     */
    private function jwtExpiration(string $token): ?int
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $json = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($json === false) {
            return null;
        }

        $claims = json_decode($json, true);

        return is_array($claims) && is_int($claims['exp'] ?? null) ? $claims['exp'] : null;
    }
}
