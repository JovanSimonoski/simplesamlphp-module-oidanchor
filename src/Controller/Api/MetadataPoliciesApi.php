<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Validation\MetadataPolicyValidator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for general (federation-wide) metadata policies, backed by FederationPolicyRepository.
 *
 * The stored per-entity-type document ({ claim: { operator: value } }) is exactly the spec's
 * EntityTypedMetadataPolicy, and the collection keyed by entity type is the spec's MetadataPolicy.
 */
class MetadataPoliciesApi extends ApiController
{
    // ---- whole collection -------------------------------------------------

    public function getAll(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $out = [];
        foreach ($this->repo()->findAll() as $entry) {
            $out[$entry->entityType] = $entry->policy;
        }

        return $this->json($out);
    }


    public function replaceAll(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object keyed by entity type.');
        }

        $validator = new MetadataPolicyValidator();
        foreach ($body as $entityType => $policy) {
            $err = $validator->validateEntityTypePolicy((string) json_encode($policy), (string) $entityType);
            if ($err !== null) {
                return $this->badRequest(sprintf('"%s": %s', $entityType, $err));
            }
        }

        $repo = $this->repo();
        // Replace semantics: drop entity types not present, upsert the rest.
        foreach ($repo->findAll() as $entry) {
            if (!array_key_exists($entry->entityType, $body)) {
                $repo->delete($entry->entityType);
            }
        }
        foreach ($body as $entityType => $policy) {
            $repo->upsert((string) $entityType, is_array($policy) ? $policy : []);
        }

        Logger::info('oidanchor: API general metadata policies replaced');

        return $this->getAll($request);
    }


    // ---- per entity type --------------------------------------------------

    public function getForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        $entry = $this->repo()->findByEntityType($entityType);
        if ($entry === null) {
            return $this->notFound(sprintf('No metadata policy for entity type "%s".', $entityType));
        }

        return $this->json($entry->policy);
    }


    public function putForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        $policy = $this->decodeJson($request);
        if (!is_array($policy)) {
            return $this->badRequest('Body must be a JSON object of claim → operators.');
        }

        if (($err = $this->validate($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $this->repo()->upsert($entityType, $policy);
        Logger::info(sprintf('oidanchor: API metadata policy set for "%s"', $entityType));

        return $this->json($policy);
    }


    public function addForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        $add = $this->decodeJson($request);
        if (!is_array($add)) {
            return $this->badRequest('Body must be a JSON object of claim → operators.');
        }

        $policy = $this->currentPolicy($entityType);
        foreach ($add as $claim => $operators) {
            $policy[$claim] = $operators;
        }

        if (($err = $this->validate($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $this->repo()->upsert($entityType, $policy);

        return $this->json($policy);
    }


    public function deleteForType(Request $request, string $entityType): Response
    {
        $this->requireAdmin();

        $this->repo()->delete($entityType);
        Logger::info(sprintf('oidanchor: API metadata policy deleted for "%s"', $entityType));

        return new Response('', Response::HTTP_NO_CONTENT);
    }


    // ---- per claim --------------------------------------------------------

    public function getClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        $policy = $this->currentPolicy($entityType);
        if (!array_key_exists($claim, $policy)) {
            return $this->notFound(sprintf('No policy for "%s"."%s".', $entityType, $claim));
        }

        return $this->json($policy[$claim]);
    }


    public function putClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        $entry = $this->decodeJson($request);
        if (!is_array($entry)) {
            return $this->badRequest('Body must be a JSON object of operator → value.');
        }

        $policy = $this->currentPolicy($entityType);
        $policy[$claim] = $entry;

        if (($err = $this->validate($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $this->repo()->upsert($entityType, $policy);

        return $this->json($entry);
    }


    public function addOperators(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        $ops = $this->decodeJson($request);
        if (!is_array($ops)) {
            return $this->badRequest('Body must be a JSON object of operator → value.');
        }

        $policy = $this->currentPolicy($entityType);
        $existing = is_array($policy[$claim] ?? null) ? $policy[$claim] : [];
        foreach ($ops as $operator => $value) {
            $existing[$operator] = $value;
        }
        $policy[$claim] = $existing;

        if (($err = $this->validate($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $this->repo()->upsert($entityType, $policy);

        return $this->json($policy[$claim]);
    }


    public function deleteClaim(Request $request, string $entityType, string $claim): Response
    {
        $this->requireAdmin();

        $policy = $this->currentPolicy($entityType);
        unset($policy[$claim]);
        $this->repo()->upsert($entityType, $policy);

        return new Response('', Response::HTTP_NO_CONTENT);
    }


    // ---- per operator -----------------------------------------------------

    public function getOperator(Request $request, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        $policy = $this->currentPolicy($entityType);
        if (!isset($policy[$claim]) || !is_array($policy[$claim]) || !array_key_exists($operator, $policy[$claim])) {
            return $this->notFound(sprintf('No operator "%s" for "%s"."%s".', $operator, $entityType, $claim));
        }

        return $this->json($policy[$claim][$operator]);
    }


    public function putOperator(Request $request, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        $value = $this->decodeJson($request);

        $policy = $this->currentPolicy($entityType);
        $existing = is_array($policy[$claim] ?? null) ? $policy[$claim] : [];
        $existing[$operator] = $value;
        $policy[$claim] = $existing;

        if (($err = $this->validate($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $this->repo()->upsert($entityType, $policy);

        return $this->json($value);
    }


    public function deleteOperator(Request $request, string $entityType, string $claim, string $operator): Response
    {
        $this->requireAdmin();

        $policy = $this->currentPolicy($entityType);
        if (isset($policy[$claim]) && is_array($policy[$claim])) {
            unset($policy[$claim][$operator]);
            $this->repo()->upsert($entityType, $policy);
        }

        return new Response('', Response::HTTP_NO_CONTENT);
    }


    // -------------------------------------------------------------------------

    private function repo(): FederationPolicyRepository
    {
        return new FederationPolicyRepository($this->buildPdo());
    }


    /**
     * @return array<string,mixed>
     */
    private function currentPolicy(string $entityType): array
    {
        $entry = $this->repo()->findByEntityType($entityType);

        return $entry !== null ? $entry->policy : [];
    }


    /**
     * @param array<string,mixed> $policy
     */
    private function validate(string $entityType, array $policy): ?string
    {
        return (new MetadataPolicyValidator())->validateEntityTypePolicy(
            (string) json_encode($policy),
            $entityType,
        );
    }
}
