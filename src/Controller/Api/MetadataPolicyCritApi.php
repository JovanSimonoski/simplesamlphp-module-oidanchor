<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Service\MetadataPolicyCritService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for the `metadata_policy_crit` claim — the metadata policy operators a consumer
 * must understand. The list is emitted in every issued subordinate statement that carries a
 * metadata_policy claim.
 *
 * Note: the spec also declares an empty stub path `/subordinates/metadata-policies-crit` with
 * no operations; only `/subordinates/metadata-policy-crit` is implementable.
 */
class MetadataPolicyCritApi extends ApiController
{
    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->service()->all());
    }


    public function replace(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON array of operator names.');
        }

        try {
            $operators = $this->service()->replace($body);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        Logger::info('oidanchor: API metadata_policy_crit replaced');

        return $this->json($operators);
    }


    public function create(Request $request): Response
    {
        $this->requireAdmin();

        $operator = $this->decodeJson($request);

        try {
            $this->service()->add($operator);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API critical metadata policy operator added: %s', (string) $operator));

        return new Response('', Response::HTTP_CREATED);
    }


    public function delete(Request $request, string $operator): Response
    {
        $this->requireAdmin();

        $this->service()->remove($operator);
        Logger::info(sprintf('oidanchor: API critical metadata policy operator deleted: %s', $operator));

        return $this->noContent();
    }


    private function service(): MetadataPolicyCritService
    {
        return new MetadataPolicyCritService($this->buildPdo());
    }
}
