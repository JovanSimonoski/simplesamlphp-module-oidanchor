<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\AuthorityHintRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for the authority hints published in the TA's entity configuration.
 * When at least one hint is stored, the store supersedes the config file's authority_hints.
 */
class AuthorityHintsApi extends ApiController
{
    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->repo()->findAll());
    }


    public function create(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        if ($entityId === '' || !$this->isHttpUrl($entityId)) {
            return $this->badRequest('entity_id is required and must be a URL.');
        }

        $description = isset($body['description']) ? (string) $body['description'] : null;

        try {
            $id = $this->repo()->create($entityId, $description);
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API authority hint created: %s', $entityId));

        return $this->json($this->repo()->findById($id), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $authorityHintID): JsonResponse
    {
        $this->requireAdmin();

        $id   = $this->internalId($authorityHintID);
        $hint = $id !== null ? $this->repo()->findById($id) : null;

        if ($hint === null) {
            return $this->notFound(sprintf('Authority hint "%s" not found.', $authorityHintID));
        }

        return $this->json($hint);
    }


    public function update(Request $request, string $authorityHintID): JsonResponse
    {
        $this->requireAdmin();

        $id   = $this->internalId($authorityHintID);
        $hint = $id !== null ? $this->repo()->findById($id) : null;

        if ($hint === null || $id === null) {
            return $this->notFound(sprintf('Authority hint "%s" not found.', $authorityHintID));
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        if ($entityId === '' || !$this->isHttpUrl($entityId)) {
            return $this->badRequest('entity_id is required and must be a URL.');
        }

        $existing = $this->repo()->findByEntityIdExcept($entityId, $id);
        if ($existing) {
            return $this->conflict(sprintf('Authority hint "%s" already exists.', $entityId));
        }

        $this->repo()->update($id, $entityId, isset($body['description']) ? (string) $body['description'] : null);
        Logger::info(sprintf('oidanchor: API authority hint updated: %s', $entityId));

        return $this->json($this->repo()->findById($id));
    }


    public function delete(Request $request, string $authorityHintID): Response
    {
        $this->requireAdmin();

        $id = $this->internalId($authorityHintID);
        if ($id !== null && $this->repo()->findById($id) !== null) {
            $this->repo()->delete($id);
            Logger::info(sprintf('oidanchor: API authority hint deleted: %s', $authorityHintID));
        }

        // The spec declares only 204 and 500 for this operation — deleting an absent hint is a no-op.
        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    private function repo(): AuthorityHintRepository
    {
        return new AuthorityHintRepository($this->buildPdo());
    }


    private function isHttpUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && in_array($parsed['scheme'], ['http', 'https'], true)
            && $parsed['host'] !== '';
    }
}
