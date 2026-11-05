<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller\Api;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\Api\TrustMarkIssuanceApi;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSpecRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(TrustMarkIssuanceApi::class)]
final class TrustMarkIssuanceApiTest extends TestCase
{
    private const string TYPE = 'https://ta.example.org/tm/member';

    private const string OLD = 'https://old.example.org';

    private const string NEW = 'https://new.example.org';


    private string $specId;


    protected function setUp(): void
    {
        parent::setUp();

        $dsn = $this->useFileDatabase();
        $this->preloadModuleConfig([
            'database_dsn'       => $dsn,
            'api_admin_username' => 'gateway',
            'api_admin_password' => 's3cret',
        ]);

        $this->specId = (string) (new TrustMarkSpecRepository($this->pdo))->create([
            'trust_mark_type' => self::TYPE,
            'lifetime'        => 3600,
        ]);
    }


    public function testCreatingAnActiveSubjectIssuesAMark(): void
    {
        $response = $this->api()->createSubject($this->request('POST', ['entity_id' => self::OLD, 'status' => 'active']), $this->specId);

        $this->assertSame(201, $response->getStatusCode());
        $this->assertNotNull($this->issued()->findActive(self::TYPE, self::OLD));
    }


    public function testRenamingAnActiveSubjectRevokesTheMarkUnderTheOldEntityId(): void
    {
        $subjectId = $this->createActiveSubject(self::OLD);

        $response = $this->api()->updateSubject(
            $this->request('PUT', ['entity_id' => self::NEW, 'status' => 'active']),
            $this->specId,
            $subjectId,
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($this->issued()->findActive(self::TYPE, self::OLD), 'The old entity kept an active mark.');
        $this->assertNotNull($this->issued()->findActive(self::TYPE, self::NEW));
    }


    public function testRenamingAndBlockingRevokesBothMarks(): void
    {
        $subjectId = $this->createActiveSubject(self::OLD);

        $this->api()->updateSubject(
            $this->request('PUT', ['entity_id' => self::NEW, 'status' => 'blocked']),
            $this->specId,
            $subjectId,
        );

        $this->assertNull($this->issued()->findActive(self::TYPE, self::OLD));
        $this->assertNull($this->issued()->findActive(self::TYPE, self::NEW));
    }


    public function testFailedIssuanceOnCreateIsReportedAndCreatesNothing(): void
    {
        $this->breakSigning();

        $response = $this->api()->createSubject($this->request('POST', ['entity_id' => self::OLD, 'status' => 'active']), $this->specId);

        $this->assertSame(500, $response->getStatusCode());
        $this->assertNull((new TrustMarkSubjectRepository($this->pdo))->findByTypeAndEntity(self::TYPE, self::OLD));
    }


    public function testFailedIssuanceOnActivationLeavesTheStatusUnchanged(): void
    {
        $created = $this->api()->createSubject($this->request('POST', ['entity_id' => self::OLD, 'status' => 'pending']), $this->specId);
        $this->assertSame(201, $created->getStatusCode());
        $subjectId = (string) json_decode((string) $created->getContent(), true)['id'];

        $this->breakSigning();
        $request = Request::create('/api/v1/admin/trust-marks/issuance', 'PUT', server: [
            'PHP_AUTH_USER' => 'gateway',
            'PHP_AUTH_PW'   => 's3cret',
        ], content: 'active');

        $response = $this->api()->changeSubjectStatus($request, $this->specId, $subjectId);

        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame(
            'pending',
            (new TrustMarkSubjectRepository($this->pdo))->findByTypeAndEntity(self::TYPE, self::OLD)['status'] ?? null,
        );
        $this->assertNull($this->issued()->findActive(self::TYPE, self::OLD));
    }


    /**
     * Point the module at a signing key file that is not a key. Nothing has signed yet, so the
     * key store is empty and the next issuance tries (and fails) to import it.
     */
    private function breakSigning(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'oidanchor-bad-key-');
        $this->assertIsString($file);
        file_put_contents($file, 'not a PEM key');
        register_shutdown_function(static fn() => @unlink($file));

        $config = Configuration::getConfig('module_oidanchor.php')->toArray();
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(['signing_key_file' => $file] + $config),
            'module_oidanchor.php',
        );
    }


    private function createActiveSubject(string $entityId): string
    {
        $response = $this->api()->createSubject($this->request('POST', ['entity_id' => $entityId, 'status' => 'active']), $this->specId);

        return (string) json_decode((string) $response->getContent(), true)['id'];
    }


    /**
     * @param array<string,mixed> $body
     */
    private function request(string $method, array $body): Request
    {
        return Request::create('/api/v1/admin/trust-marks/issuance', $method, server: [
            'PHP_AUTH_USER' => 'gateway',
            'PHP_AUTH_PW'   => 's3cret',
            'CONTENT_TYPE'  => 'application/json',
        ], content: (string) json_encode($body));
    }


    private function api(): TrustMarkIssuanceApi
    {
        return new TrustMarkIssuanceApi(Configuration::loadFromArray([]));
    }


    private function issued(): IssuedTrustMarkRepository
    {
        return new IssuedTrustMarkRepository($this->pdo);
    }
}
