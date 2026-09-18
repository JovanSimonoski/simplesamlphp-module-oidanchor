<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSpecRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkDelegationService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkIssuanceService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for Trust Mark issuance specs and their subjects.
 *
 * A spec is the issuance template for one trust mark type; its subjects are the entities the
 * TA issues that mark to. Setting a subject's status to `active` issues the mark; any other
 * status revokes the marks it holds, which the public /trust_mark_status endpoint reflects.
 */
class TrustMarkIssuanceApi extends ApiController
{
    private const ELIGIBILITY_MODES = ['db_only', 'check_only', 'db_or_check', 'db_and_check', 'custom'];


    // ---- issuance specs ------------------------------------------------------

    public function listSpecs(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->specRepo()->findAll());
    }


    public function createSpec(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $trustMarkType = trim((string) ($body['trust_mark_type'] ?? ''));
        if ($trustMarkType === '') {
            return $this->badRequest('trust_mark_type is required.');
        }

        if (($err = $this->validateSpec($body, $trustMarkType)) !== null) {
            return $this->badRequest($err);
        }

        if ($this->specRepo()->findByType($trustMarkType) !== null) {
            return $this->conflict(sprintf('An issuance spec for "%s" already exists.', $trustMarkType));
        }

        try {
            $id = $this->specRepo()->create($this->normalizeSpec($body) + ['trust_mark_type' => $trustMarkType]);
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark issuance spec created: %s', $trustMarkType));

        return $this->json($this->specRepo()->findById($id), JsonResponse::HTTP_CREATED);
    }


    public function getSpec(Request $request, string $trustMarkSpecID): JsonResponse
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        return $this->json($spec);
    }


    /**
     * PUT — replace the whole spec.
     */
    public function updateSpec(Request $request, string $trustMarkSpecID): JsonResponse
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $trustMarkType = trim((string) ($body['trust_mark_type'] ?? ''));
        if ($trustMarkType === '') {
            return $this->badRequest('trust_mark_type is required.');
        }

        if (($err = $this->validateSpec($body, $trustMarkType)) !== null) {
            return $this->badRequest($err);
        }

        $conflicting = $this->specRepo()->findByType($trustMarkType);
        if ($conflicting !== null && (int) $conflicting['id'] !== (int) $spec['id']) {
            return $this->conflict(sprintf('An issuance spec for "%s" already exists.', $trustMarkType));
        }

        $fields = $this->normalizeSpec($body) + [
            'trust_mark_type'    => $trustMarkType,
            'description'        => null,
            'lifetime'           => null,
            'ref'                => null,
            'logo_uri'           => null,
            'delegation_jwt'     => null,
            'additional_claims'  => null,
            'eligibility_config' => null,
            'cache_ttl'          => 0,
        ];

        $this->specRepo()->update((int) $spec['id'], $fields);
        Logger::info(sprintf('oidanchor: API trust mark issuance spec updated: %s', $trustMarkType));

        return $this->json($this->specRepo()->findById((int) $spec['id']));
    }


    /**
     * PATCH — merge the supplied members.
     */
    public function patchSpec(Request $request, string $trustMarkSpecID): JsonResponse
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $trustMarkType = array_key_exists('trust_mark_type', $body)
            ? trim((string) $body['trust_mark_type'])
            : (string) $spec['trust_mark_type'];

        if ($trustMarkType === '') {
            return $this->badRequest('trust_mark_type must not be empty.');
        }

        if (($err = $this->validateSpec($body, $trustMarkType)) !== null) {
            return $this->badRequest($err);
        }

        $fields = $this->normalizeSpec($body);
        if ($fields === []) {
            return $this->badRequest('No updatable members supplied.');
        }

        $this->specRepo()->update((int) $spec['id'], $fields);
        Logger::info(sprintf('oidanchor: API trust mark issuance spec patched: %d', (int) $spec['id']));

        return $this->json($this->specRepo()->findById((int) $spec['id']));
    }


    public function deleteSpec(Request $request, string $trustMarkSpecID): Response
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        $this->specRepo()->delete((int) $spec['id']);
        Logger::info(sprintf('oidanchor: API trust mark issuance spec deleted: %s', (string) $spec['trust_mark_type']));

        return $this->noContent();
    }


    // ---- subjects ------------------------------------------------------------

    public function listSubjects(Request $request, string $trustMarkSpecID): JsonResponse
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        $status = trim((string) $request->query->get('status', '')) ?: null;

        return $this->json(array_map(
            static fn(array $subject): array => self::subjectToApi($subject),
            $this->subjectRepo()->findBySpec((int) $spec['id'], $status),
        ));
    }


    /**
     * POST — create a subject. An `active` subject gets its trust mark issued immediately.
     */
    public function createSubject(Request $request, string $trustMarkSpecID): JsonResponse
    {
        $this->requireAdmin();

        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        $status   = trim((string) ($body['status'] ?? ''));

        if ($entityId === '') {
            return $this->badRequest('entity_id is required.');
        }
        if (!in_array($status, TrustMarkSubjectRepository::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', TrustMarkSubjectRepository::STATUSES) . '.');
        }

        try {
            $id = $this->subjectRepo()->create(
                (int) $spec['id'],
                $entityId,
                $status,
                isset($body['description']) ? (string) $body['description'] : null,
                isset($body['additional_claims']) && is_array($body['additional_claims'])
                    ? $body['additional_claims']
                    : null,
            );
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        $this->applyStatusEffects((int) $spec['id'], $id, $status);
        Logger::info(sprintf('oidanchor: API trust mark subject created: %s', $entityId));

        return $this->json(
            self::subjectToApi($this->subjectRepo()->findById((int) $spec['id'], $id)),
            JsonResponse::HTTP_CREATED,
        );
    }


    public function getSubject(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        return $this->json(self::subjectToApi($subject));
    }


    public function updateSubject(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        $status   = trim((string) ($body['status'] ?? ''));

        if ($entityId === '') {
            return $this->badRequest('entity_id is required.');
        }
        if (!in_array($status, TrustMarkSubjectRepository::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', TrustMarkSubjectRepository::STATUSES) . '.');
        }

        $this->subjectRepo()->update((int) $subject['id'], [
            'entity_id'         => $entityId,
            'status'            => $status,
            'description'       => isset($body['description']) ? (string) $body['description'] : null,
            'additional_claims' => isset($body['additional_claims']) && is_array($body['additional_claims'])
                ? $body['additional_claims']
                : null,
        ]);

        $this->applyStatusEffects((int) $spec['id'], (int) $subject['id'], $status, (string) $subject['entity_id'], (string) $spec['trust_mark_type']);
        Logger::info(sprintf('oidanchor: API trust mark subject updated: %s', $entityId));

        return $this->json(self::subjectToApi($this->subjectRepo()->findById((int) $spec['id'], (int) $subject['id'])));
    }


    public function deleteSubject(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): Response
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $this->issuanceService()->revokeMarksForSubject(
            (string) $spec['trust_mark_type'],
            (string) $subject['entity_id'],
            'subject removed',
        );
        $this->subjectRepo()->delete((int) $subject['id']);
        Logger::info(sprintf('oidanchor: API trust mark subject deleted: %s', (string) $subject['entity_id']));

        return $this->noContent();
    }


    /**
     * PUT /subjects/{id}/status — issue or revoke the subject's marks accordingly.
     */
    public function changeSubjectStatus(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $status = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if (!in_array($status, TrustMarkSubjectRepository::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', TrustMarkSubjectRepository::STATUSES) . '.');
        }

        $this->subjectRepo()->setStatus((int) $subject['id'], $status);
        $this->applyStatusEffects(
            (int) $spec['id'],
            (int) $subject['id'],
            $status,
            (string) $subject['entity_id'],
            (string) $spec['trust_mark_type'],
        );

        Logger::info(sprintf(
            'oidanchor: API trust mark subject status changed: %s -> %s',
            (string) $subject['entity_id'],
            $status,
        ));

        return $this->json(self::subjectToApi($this->subjectRepo()->findById((int) $spec['id'], (int) $subject['id'])));
    }


    // ---- subject additional claims --------------------------------------------

    public function getSubjectClaims(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $claims = $subject['additional_claims'] ?? [];

        return $this->json($claims === [] ? new \stdClass() : $claims);
    }


    public function updateSubjectClaims(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body) || array_is_list($body)) {
            return $this->badRequest('Body must be a JSON object of claim → value.');
        }

        $this->subjectRepo()->update((int) $subject['id'], ['additional_claims' => $body]);
        Logger::info(sprintf('oidanchor: API trust mark subject claims replaced: %s', (string) $subject['entity_id']));

        return $this->json($body === [] ? new \stdClass() : $body);
    }


    /**
     * POST — merge the spec's general claims into the subject's claims (subject wins on conflict).
     */
    public function copySubjectClaims(Request $request, string $trustMarkSpecID, string $trustMarkSubjectID): JsonResponse
    {
        $this->requireAdmin();

        [$spec, $subject] = $this->findSpecAndSubject($trustMarkSpecID, $trustMarkSubjectID);
        if ($spec === null) {
            return $this->specNotFound($trustMarkSpecID);
        }
        if ($subject === null) {
            return $this->subjectNotFound($trustMarkSubjectID);
        }

        $merged = array_merge(
            is_array($spec['additional_claims'] ?? null) ? $spec['additional_claims'] : [],
            is_array($subject['additional_claims'] ?? null) ? $subject['additional_claims'] : [],
        );

        $this->subjectRepo()->update((int) $subject['id'], ['additional_claims' => $merged]);
        Logger::info(sprintf('oidanchor: API trust mark subject claims merged: %s', (string) $subject['entity_id']));

        return $this->json($merged === [] ? new \stdClass() : $merged);
    }


    // -------------------------------------------------------------------------

    /**
     * Issue the mark when the subject becomes eligible; revoke its marks otherwise.
     */
    private function applyStatusEffects(
        int $specId,
        int $subjectId,
        string $status,
        ?string $previousEntityId = null,
        ?string $trustMarkType = null,
    ): void {
        try {
            if ($status === 'active') {
                $this->issuanceService()->issueForSubject($specId, $subjectId);

                return;
            }

            $spec    = $this->specRepo()->findById($specId);
            $subject = $this->subjectRepo()->findById($specId, $subjectId);
            if ($spec === null || $subject === null) {
                return;
            }

            $this->issuanceService()->revokeMarksForSubject(
                (string) $spec['trust_mark_type'],
                (string) $subject['entity_id'],
                sprintf('subject status changed to %s', $status),
            );

            // An entity_id change leaves marks behind under the old subject name.
            if ($previousEntityId !== null && $trustMarkType !== null && $previousEntityId !== (string) $subject['entity_id']) {
                $this->issuanceService()->revokeMarksForSubject($trustMarkType, $previousEntityId, 'subject entity_id changed');
            }
        } catch (Throwable $e) {
            Logger::warning('oidanchor: trust mark issuance side effect failed: ' . $e->getMessage());
        }
    }


    /**
     * @param array<string,mixed> $body
     */
    private function validateSpec(array $body, string $trustMarkType): ?string
    {
        foreach (['lifetime', 'cache_ttl'] as $field) {
            if (array_key_exists($field, $body) && (!is_int($body[$field]) || $body[$field] < 0)) {
                return sprintf('%s must be a non-negative integer.', $field);
            }
        }

        if (array_key_exists('additional_claims', $body)
            && ($body['additional_claims'] !== null && !is_array($body['additional_claims']))
        ) {
            return 'additional_claims must be a JSON object.';
        }

        if (array_key_exists('eligibility_config', $body) && $body['eligibility_config'] !== null) {
            if (!is_array($body['eligibility_config'])) {
                return 'eligibility_config must be a JSON object.';
            }
            $mode = $body['eligibility_config']['mode'] ?? 'db_only';
            if (!in_array($mode, self::ELIGIBILITY_MODES, true)) {
                return 'eligibility_config.mode must be one of: ' . implode(', ', self::ELIGIBILITY_MODES) . '.';
            }
        }

        // A supplied delegation must actually authorise this TA to issue this type.
        if (isset($body['delegation_jwt']) && is_string($body['delegation_jwt']) && trim($body['delegation_jwt']) !== '') {
            try {
                (new TrustMarkDelegationService($this->moduleConfig(), $this->buildPdo()))->validate(
                    trim($body['delegation_jwt']),
                    $trustMarkType,
                    (new FederationKeyService($this->moduleConfig(), $this->buildPdo()))->entityId(),
                );
            } catch (InvalidArgumentException $e) {
                return $e->getMessage();
            } catch (Throwable $e) {
                return 'Could not validate delegation_jwt: ' . $e->getMessage();
            }
        }

        return null;
    }


    /**
     * @param array<string,mixed> $body
     * @return array<string,mixed>
     */
    private function normalizeSpec(array $body): array
    {
        $fields = [];

        foreach (['trust_mark_type', 'description', 'ref', 'logo_uri', 'delegation_jwt'] as $field) {
            if (array_key_exists($field, $body)) {
                $value = $body[$field];
                $fields[$field] = is_string($value) && trim($value) !== '' ? trim($value) : null;
            }
        }

        foreach (['lifetime', 'cache_ttl'] as $field) {
            if (array_key_exists($field, $body)) {
                $fields[$field] = is_int($body[$field]) ? $body[$field] : null;
            }
        }

        foreach (['additional_claims', 'eligibility_config'] as $field) {
            if (array_key_exists($field, $body)) {
                $fields[$field] = is_array($body[$field]) ? $body[$field] : null;
            }
        }

        if (array_key_exists('cache_ttl', $fields) && $fields['cache_ttl'] === null) {
            $fields['cache_ttl'] = 0;
        }

        return $fields;
    }


    /**
     * The spec's TrustMarkSubject shape (the internal spec_id is not part of it).
     *
     * @param array<string,mixed> $subject
     * @return array<string,mixed>
     */
    private static function subjectToApi(array $subject): array
    {
        unset($subject['spec_id']);

        return $subject;
    }


    /**
     * @return array{0: array<string,mixed>|null, 1: array<string,mixed>|null}
     */
    private function findSpecAndSubject(string $trustMarkSpecID, string $trustMarkSubjectID): array
    {
        $spec = $this->findSpec($trustMarkSpecID);
        if ($spec === null) {
            return [null, null];
        }

        $subjectId = $this->internalId($trustMarkSubjectID);
        $subject   = $subjectId !== null ? $this->subjectRepo()->findById((int) $spec['id'], $subjectId) : null;

        return [$spec, $subject];
    }


    /**
     * @return array<string,mixed>|null
     */
    private function findSpec(string $trustMarkSpecID): ?array
    {
        $id = $this->internalId($trustMarkSpecID);

        return $id !== null ? $this->specRepo()->findById($id) : null;
    }


    private function specNotFound(string $trustMarkSpecID): JsonResponse
    {
        return $this->notFound(sprintf('Trust mark issuance spec "%s" not found.', $trustMarkSpecID));
    }


    private function subjectNotFound(string $trustMarkSubjectID): JsonResponse
    {
        return $this->notFound(sprintf('Trust mark subject "%s" not found.', $trustMarkSubjectID));
    }


    private function specRepo(): TrustMarkSpecRepository
    {
        return new TrustMarkSpecRepository($this->buildPdo());
    }


    private function subjectRepo(): TrustMarkSubjectRepository
    {
        return new TrustMarkSubjectRepository($this->buildPdo());
    }


    private function issuanceService(): TrustMarkIssuanceService
    {
        $pdo = $this->buildPdo();

        return new TrustMarkIssuanceService(new FederationKeyService($this->moduleConfig(), $pdo), $pdo);
    }
}
