<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkIssuer;
use SimpleSAML\Module\oidanchor\Validation\IssuedTrustMarkValidator;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Admin UI controller for issued Trust Marks: listing, issuance, viewing and revocation.
 *
 * All methods require admin authentication; state-changing methods require a valid CSRF token.
 */
class AdminTrustMarks extends AdminController
{
    protected const string FLASH_KEY = 'oidanchor_tm_flash';


    public function list(Request $request): Template
    {
        $this->requireAdmin();

        $filterType   = trim((string) $request->query->get('trust_mark_type', '')) ?: null;
        $filterSub    = trim((string) $request->query->get('sub', '')) ?: null;
        $filterStatus = trim((string) $request->query->get('status', '')) ?: null;

        $issuedRepo = $this->issuedRepository();
        $typeRepo   = $this->typeRepository();

        $marks = $issuedRepo->findAll($filterType, $filterSub, $filterStatus);

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_list.twig');
        $t->data['marks']        = $marks;
        $t->data['types']        = $typeRepo->findAll();
        $t->data['filter']       = ['trust_mark_type' => $filterType, 'sub' => $filterSub, 'status' => $filterStatus];
        $t->data['issueUrl']     = Module::getModuleURL('oidanchor/admin/trust-marks/issue');
        $t->data['listUrl']      = Module::getModuleURL('oidanchor/admin/trust-marks');

        return $this->page($t);
    }


    public function issue(Request $request): Template|RedirectResponse
    {
        $this->requireAdmin();

        $errors   = [];
        $formData = ['trust_mark_type' => '', 'sub' => '', 'exp' => '', 'extra_claims' => ''];

        if ($request->isMethod('POST')) {
            if (!$this->assertCsrf($request)) {
                return $this->csrfFailure('oidanchor/admin/trust-marks');
            }

            $formData = [
                'trust_mark_type' => trim((string) $request->request->get('trust_mark_type', '')),
                'sub'           => trim((string) $request->request->get('sub', '')),
                'exp'           => trim((string) $request->request->get('exp', '')),
                'extra_claims'  => trim((string) $request->request->get('extra_claims', '')),
            ];

            $errors = (new IssuedTrustMarkValidator())->validate($formData);

            $typeRepo = $this->typeRepository();
            if (!isset($errors['trust_mark_type']) && $typeRepo->findById($formData['trust_mark_type']) === null) {
                $errors['trust_mark_type'] = 'Unknown Trust Mark type. Create it in the catalog first.';
            }

            if ($errors === []) {
                try {
                    $exp = $formData['exp'] !== '' ? time() + (int) $formData['exp'] : null;

                    $extraClaims = $formData['extra_claims'] !== ''
                        ? (json_decode($formData['extra_claims'], true) ?: [])
                        : [];

                    $issuer = new TrustMarkIssuer(
                        new FederationKeyService(Configuration::getConfig('module_oidanchor.php')),
                        $typeRepo,
                        $this->issuedRepository(),
                    );

                    $mark = $issuer->issue($formData['trust_mark_type'], $formData['sub'], $exp, $extraClaims);

                    Logger::info(sprintf(
                        'oidanchor: trust mark issued: type=%s sub=%s id=%d (admin: %s)',
                        $formData['trust_mark_type'],
                        $formData['sub'],
                        (int) $mark->id,
                        $this->getAdminUsername(),
                    ));

                    $note = $this->subordinateRepository()->exists($formData['sub'])
                        ? ''
                        : ' Note: this subject is not a registered subordinate.';

                    $this->pushFlash('success', sprintf(
                        'Trust Mark issued for "%s".%s',
                        $formData['sub'],
                        $note,
                    ));

                    return new RedirectResponse(
                        Module::getModuleURL('oidanchor/admin/trust-marks/' . (int) $mark->id . '/view'),
                    );
                } catch (Throwable $e) {
                    $errors['trust_mark_type'] = 'Issuance failed: ' . $e->getMessage();
                }
            }
        }

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_form.twig');
        $t->data['title']       = 'Issue Trust Mark';
        $t->data['formData']    = $formData;
        $t->data['errors']      = $errors;
        $t->data['types']       = $this->typeRepository()->findAll();
        $t->data['actionUrl']   = Module::getModuleURL('oidanchor/admin/trust-marks/issue');
        $t->data['listUrl']     = Module::getModuleURL('oidanchor/admin/trust-marks');

        return $this->page($t);
    }


    public function view(Request $request, string $id): Template|RedirectResponse
    {
        $this->requireAdmin();

        $mark = $this->issuedRepository()->findById((int) $id);

        if ($mark === null) {
            $this->pushFlash('error', sprintf('Trust Mark #%s not found.', $id));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        $decoded = $this->decodeForDisplay($mark->jwt);

        $t = new Template($this->config, 'oidanchor:admin_trust_marks_view.twig');
        $t->data['mark']           = $mark;
        $t->data['decodedHeader']  = $decoded['header'];
        $t->data['decodedPayload'] = $decoded['payload'];
        $t->data['decodeNote']     = $decoded['note'];
        $t->data['listUrl']        = Module::getModuleURL('oidanchor/admin/trust-marks');
        $t->data['revokeUrl']      = Module::getModuleURL('oidanchor/admin/trust-marks/' . (int) $mark->id . '/revoke');

        return $this->page($t);
    }


    public function revoke(Request $request, string $id): RedirectResponse
    {
        $this->requireAdmin();

        if (!$this->assertCsrf($request)) {
            return $this->csrfFailure('oidanchor/admin/trust-marks');
        }

        $issuedRepo = $this->issuedRepository();
        $mark       = $issuedRepo->findById((int) $id);

        if ($mark === null) {
            $this->pushFlash('error', sprintf('Trust Mark #%s not found.', $id));

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        if ($mark->status === 'revoked') {
            $this->pushFlash('error', 'This Trust Mark is already revoked.');

            return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
        }

        $reason = trim((string) $request->request->get('reason', '')) ?: null;
        $issuedRepo->revoke((int) $mark->id, $reason);

        Logger::info(sprintf(
            'oidanchor: trust mark revoked: id=%d type=%s sub=%s (admin: %s)',
            (int) $mark->id,
            $mark->trustMarkType,
            $mark->sub,
            $this->getAdminUsername(),
        ));

        $this->pushFlash('success', sprintf('Trust Mark #%d revoked.', (int) $mark->id));

        return new RedirectResponse(Module::getModuleURL('oidanchor/admin/trust-marks'));
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Decode a Trust Mark for read-only admin display: prefer the library parser, fall back to a
     * lenient base64 decode when strict parsing rejects the token (e.g. an expired or revoked mark).
     *
     * @return array{header: string, payload: string, note: ?string}
     */
    private function decodeForDisplay(string $jwt): array
    {
        try {
            $mark = (new Federation())->trustMarkFactory()->fromToken($jwt);

            return [
                'header'  => $this->pretty($mark->getHeader()),
                'payload' => $this->pretty($mark->getPayload()),
                'note'    => null,
            ];
        } catch (Throwable $e) {
            $parts = explode('.', $jwt);

            return [
                'header'  => $this->prettyFromSegment($parts[0]),
                'payload' => $this->prettyFromSegment($parts[1] ?? ''),
                'note'    => 'Shown via lenient decode (strict parse failed: ' . $e->getMessage() . ').',
            ];
        }
    }


    /**
     * @param array<string,mixed> $data
     */
    private function pretty(array $data): string
    {
        return (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }


    private function prettyFromSegment(string $segment): string
    {
        if ($segment === '') {
            return '';
        }

        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }

        $json = json_decode($decoded, true);

        return is_array($json) ? $this->pretty($json) : $decoded;
    }


    private function typeRepository(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository(PdoFactory::get(Configuration::getConfig('module_oidanchor.php')));
    }


    private function issuedRepository(): IssuedTrustMarkRepository
    {
        return new IssuedTrustMarkRepository(PdoFactory::get(Configuration::getConfig('module_oidanchor.php')));
    }


    private function subordinateRepository(): SubordinateRepository
    {
        return new SubordinateRepository(PdoFactory::get(Configuration::getConfig('module_oidanchor.php')));
    }
}
