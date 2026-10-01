<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The Constraints sub-resource, identical in shape for the general (federation-wide) and the
 * per-subordinate variants: the whole object plus the three members max_path_length,
 * naming_constraints and allowed_entity_types.
 *
 * Implementors provide readConstraints() / writeConstraints().
 */
trait ConstraintsTrait
{
    /**
     * @return array<string,mixed>
     */
    abstract protected function readConstraints(): array;


    /**
     * @param array<string,mixed> $constraints
     */
    abstract protected function writeConstraints(array $constraints): void;


    // ---- whole object -----------------------------------------------------

    protected function constraintsIndex(): JsonResponse
    {
        $constraints = $this->readConstraints();

        return $this->json($constraints === [] ? new \stdClass() : $constraints);
    }


    protected function constraintsReplace(Request $request): JsonResponse
    {
        $body = $this->decodeJson($request);
        if (!is_array($body) || array_is_list($body)) {
            return $this->badRequest('Body must be a Constraints JSON object.');
        }

        try {
            (new ConstraintsService($this->buildPdo()))->validate($body);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        $this->writeConstraints($body);

        return $this->constraintsIndex();
    }


    protected function constraintsDelete(): Response
    {
        $this->writeConstraints([]);

        return $this->noContent();
    }


    // ---- max_path_length --------------------------------------------------

    protected function maxPathLengthGet(): JsonResponse
    {
        $constraints = $this->readConstraints();
        if (!array_key_exists(ConstraintsService::MAX_PATH_LENGTH, $constraints)) {
            return $this->notFound('max_path_length is not set.');
        }

        return $this->json($constraints[ConstraintsService::MAX_PATH_LENGTH]);
    }


    protected function maxPathLengthSet(Request $request): JsonResponse
    {
        $value = $this->decodeJson($request);

        try {
            $validated = ConstraintsService::validateMaxPathLength($value);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        $constraints = $this->readConstraints();
        $constraints[ConstraintsService::MAX_PATH_LENGTH] = $validated;
        $this->writeConstraints($constraints);

        return $this->json($validated);
    }


    protected function maxPathLengthDelete(): Response
    {
        $constraints = $this->readConstraints();
        unset($constraints[ConstraintsService::MAX_PATH_LENGTH]);
        $this->writeConstraints($constraints);

        return $this->noContent();
    }


    // ---- naming_constraints -----------------------------------------------

    protected function namingConstraintsGet(): JsonResponse
    {
        $constraints = $this->readConstraints();
        if (!array_key_exists(ConstraintsService::NAMING_CONSTRAINTS, $constraints)) {
            return $this->notFound('naming_constraints are not set.');
        }

        return $this->json($constraints[ConstraintsService::NAMING_CONSTRAINTS]);
    }


    protected function namingConstraintsSet(Request $request): JsonResponse
    {
        $value = $this->decodeJson($request);

        try {
            $validated = ConstraintsService::validateNamingConstraints($value);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        $constraints = $this->readConstraints();
        $constraints[ConstraintsService::NAMING_CONSTRAINTS] = $validated;
        $this->writeConstraints($constraints);

        return $this->json($validated === [] ? new \stdClass() : $validated);
    }


    protected function namingConstraintsDelete(): Response
    {
        $constraints = $this->readConstraints();
        unset($constraints[ConstraintsService::NAMING_CONSTRAINTS]);
        $this->writeConstraints($constraints);

        return $this->noContent();
    }


    // ---- allowed_entity_types ----------------------------------------------

    protected function allowedEntityTypesGet(): JsonResponse
    {
        $constraints = $this->readConstraints();
        if (!array_key_exists(ConstraintsService::ALLOWED_ENTITY_TYPES, $constraints)) {
            return $this->notFound('allowed_entity_types are not set.');
        }

        return $this->json($constraints[ConstraintsService::ALLOWED_ENTITY_TYPES]);
    }


    protected function allowedEntityTypesSet(Request $request): JsonResponse
    {
        $value = $this->decodeJson($request);

        try {
            $validated = ConstraintsService::validateAllowedEntityTypes($value);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        $constraints = $this->readConstraints();
        $constraints[ConstraintsService::ALLOWED_ENTITY_TYPES] = $validated;
        $this->writeConstraints($constraints);

        return $this->json($validated);
    }


    /**
     * POST — add one entity type to the allow list; returns the updated list.
     */
    protected function allowedEntityTypesAdd(Request $request): JsonResponse
    {
        $value = $this->decodeJson($request);
        if (!is_string($value) || trim($value) === '') {
            return $this->badRequest('Body must be a JSON string naming the entity type.');
        }

        $constraints = $this->readConstraints();
        $current     = $constraints[ConstraintsService::ALLOWED_ENTITY_TYPES] ?? [];
        $current[]   = trim($value);

        $constraints[ConstraintsService::ALLOWED_ENTITY_TYPES] = array_values(array_unique($current));
        $this->writeConstraints($constraints);

        return $this->json($constraints[ConstraintsService::ALLOWED_ENTITY_TYPES], JsonResponse::HTTP_CREATED);
    }


    /**
     * DELETE {entityType} — remove one entity type; returns the updated list (200).
     */
    protected function allowedEntityTypeDelete(string $entityType): JsonResponse
    {
        $constraints = $this->readConstraints();
        $current     = $constraints[ConstraintsService::ALLOWED_ENTITY_TYPES] ?? [];

        $remaining = array_values(array_filter(
            $current,
            static fn(string $known): bool => $known !== $entityType,
        ));

        $constraints[ConstraintsService::ALLOWED_ENTITY_TYPES] = $remaining;
        $this->writeConstraints($constraints);

        return $this->json($remaining);
    }
}
