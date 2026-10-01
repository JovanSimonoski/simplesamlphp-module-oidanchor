<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Module\oidanchor\Validation\MetadataPolicyValidator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The four metadata-policy granularities the spec defines — whole policy, one entity type,
 * one claim, one operator — expressed against an abstract MetadataPolicy document
 * ({ entityType: { claim: { operator: value } } }).
 *
 * Storage stays a JSON document per entity type; every write revalidates the affected
 * entity-type policy through MetadataPolicyValidator, which drives the library's
 * MetadataPolicyOperatorsEnum (operator value types and operator-combination rules) and
 * MetadataPolicyResolver::ensureFormat. Operator-level writes therefore cannot leave an
 * invalid document behind.
 *
 * Implementors provide readPolicyDocument() / writePolicyDocument().
 */
trait MetadataPolicyDocumentTrait
{
    /**
     * @return array<string,array<string,mixed>>
     */
    abstract protected function readPolicyDocument(): array;


    /**
     * @param array<string,array<string,mixed>> $document
     */
    abstract protected function writePolicyDocument(array $document): void;


    // ---- whole policy -----------------------------------------------------

    protected function policyIndex(): JsonResponse
    {
        $document = $this->readPolicyDocument();

        return $this->json($document === [] ? new \stdClass() : $document);
    }


    protected function policyReplace(Request $request): JsonResponse
    {
        $body = $this->decodeJson($request);
        if (!is_array($body) || array_is_list($body)) {
            return $this->badRequest('Body must be a JSON object keyed by entity type.');
        }

        foreach ($body as $entityType => $policy) {
            if (!is_array($policy)) {
                return $this->badRequest(sprintf('Policy for "%s" must be a JSON object.', $entityType));
            }
            if (($err = $this->validatePolicy((string) $entityType, $policy)) !== null) {
                return $this->badRequest($err);
            }
        }

        $this->writePolicyDocument($body);

        return $this->policyIndex();
    }


    // ---- one entity type --------------------------------------------------

    protected function policyForType(string $entityType): JsonResponse
    {
        $document = $this->readPolicyDocument();
        if (!array_key_exists($entityType, $document)) {
            return $this->notFound(sprintf('No metadata policy for entity type "%s".', $entityType));
        }

        return $this->json($document[$entityType] === [] ? new \stdClass() : $document[$entityType]);
    }


    protected function policyPutType(Request $request, string $entityType): JsonResponse
    {
        $policy = $this->decodeJson($request);
        if (!is_array($policy) || array_is_list($policy)) {
            return $this->badRequest('Body must be a JSON object of claim → operators.');
        }

        if (($err = $this->validatePolicy($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $document = $this->readPolicyDocument();
        $document[$entityType] = $policy;
        $this->writePolicyDocument($document);

        return $this->json($policy === [] ? new \stdClass() : $policy);
    }


    /**
     * POST — merge the supplied claims into the entity type's policy.
     */
    protected function policyAddClaims(Request $request, string $entityType): JsonResponse
    {
        $add = $this->decodeJson($request);
        if (!is_array($add) || array_is_list($add)) {
            return $this->badRequest('Body must be a JSON object of claim → operators.');
        }

        $document = $this->readPolicyDocument();
        $policy   = array_merge($document[$entityType] ?? [], $add);

        if (($err = $this->validatePolicy($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $document[$entityType] = $policy;
        $this->writePolicyDocument($document);

        return $this->json($policy);
    }


    protected function policyDeleteType(string $entityType): Response
    {
        $document = $this->readPolicyDocument();
        if (array_key_exists($entityType, $document)) {
            unset($document[$entityType]);
            $this->writePolicyDocument($document);
        }

        return $this->noContent();
    }


    // ---- one claim --------------------------------------------------------

    protected function policyGetClaim(string $entityType, string $claim): JsonResponse
    {
        $document = $this->readPolicyDocument();
        if (!isset($document[$entityType]) || !array_key_exists($claim, $document[$entityType])) {
            return $this->notFound(sprintf('No policy for "%s"."%s".', $entityType, $claim));
        }

        return $this->json($document[$entityType][$claim]);
    }


    protected function policyPutClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $entry = $this->decodeJson($request);
        if (!is_array($entry) || array_is_list($entry)) {
            return $this->badRequest('Body must be a JSON object of operator → value.');
        }

        $document = $this->readPolicyDocument();
        $policy   = $document[$entityType] ?? [];
        $policy[$claim] = $entry;

        if (($err = $this->validatePolicy($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $document[$entityType] = $policy;
        $this->writePolicyDocument($document);

        return $this->json($entry === [] ? new \stdClass() : $entry);
    }


    /**
     * POST — merge operators into the claim's policy entry.
     */
    protected function policyAddOperators(Request $request, string $entityType, string $claim): JsonResponse
    {
        $ops = $this->decodeJson($request);
        if (!is_array($ops) || array_is_list($ops)) {
            return $this->badRequest('Body must be a JSON object of operator → value.');
        }

        $document = $this->readPolicyDocument();
        $policy   = $document[$entityType] ?? [];
        $existing = is_array($policy[$claim] ?? null) ? $policy[$claim] : [];
        $policy[$claim] = array_merge($existing, $ops);

        if (($err = $this->validatePolicy($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $document[$entityType] = $policy;
        $this->writePolicyDocument($document);

        return $this->json($policy[$claim]);
    }


    protected function policyDeleteClaim(string $entityType, string $claim): Response
    {
        $document = $this->readPolicyDocument();
        if (isset($document[$entityType]) && array_key_exists($claim, $document[$entityType])) {
            unset($document[$entityType][$claim]);
            $this->writePolicyDocument($document);
        }

        return $this->noContent();
    }


    // ---- one operator -----------------------------------------------------

    protected function policyGetOperator(string $entityType, string $claim, string $operator): JsonResponse
    {
        $document = $this->readPolicyDocument();
        $entry    = $document[$entityType][$claim] ?? null;

        if (!is_array($entry) || !array_key_exists($operator, $entry)) {
            return $this->notFound(sprintf('No operator "%s" for "%s"."%s".', $operator, $entityType, $claim));
        }

        return $this->json($entry[$operator]);
    }


    /**
     * PUT — 201 when the operator is newly created, 200 when it replaces an existing value.
     */
    protected function policyPutOperator(
        Request $request,
        string $entityType,
        string $claim,
        string $operator,
    ): JsonResponse {
        if (trim($request->getContent()) === '') {
            return $this->badRequest('Body must contain the operator value as JSON.');
        }

        $value = $this->decodeJson($request);
        if ($value === null && json_last_error() !== JSON_ERROR_NONE) {
            return $this->badRequest('Body must contain the operator value as valid JSON.');
        }

        $document = $this->readPolicyDocument();
        $policy   = $document[$entityType] ?? [];
        $existing = is_array($policy[$claim] ?? null) ? $policy[$claim] : [];
        $existed  = array_key_exists($operator, $existing);

        $existing[$operator] = $value;
        $policy[$claim]      = $existing;

        if (($err = $this->validatePolicy($entityType, $policy)) !== null) {
            return $this->badRequest($err);
        }

        $document[$entityType] = $policy;
        $this->writePolicyDocument($document);

        return $this->json($value, $existed ? JsonResponse::HTTP_OK : JsonResponse::HTTP_CREATED);
    }


    protected function policyDeleteOperator(string $entityType, string $claim, string $operator): Response
    {
        $document = $this->readPolicyDocument();
        $entry    = $document[$entityType][$claim] ?? null;

        if (is_array($entry) && array_key_exists($operator, $entry)) {
            unset($document[$entityType][$claim][$operator]);
            $this->writePolicyDocument($document);
        }

        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    /**
     * @param array<string,mixed> $policy Entity-type-scoped policy ({ claim: { operator: value } }).
     */
    private function validatePolicy(string $entityType, array $policy): ?string
    {
        if ($policy === []) {
            return null;
        }

        return (new MetadataPolicyValidator())->validateEntityTypePolicy(
            (string) json_encode($policy),
            $entityType,
        );
    }
}
