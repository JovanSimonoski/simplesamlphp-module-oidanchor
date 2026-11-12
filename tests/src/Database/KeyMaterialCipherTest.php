<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;
use SimpleSAML\Module\oidanchor\Database\KeyMaterialCipher;
use SimpleSAML\Module\oidanchor\Repository\FederationKeyRepository;
use SimpleSAML\Module\oidanchor\Service\KeyManagementService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(KeyMaterialCipher::class)]
#[CoversClass(FederationKeyRepository::class)]
final class KeyMaterialCipherTest extends TestCase
{
    private const string SECRET = 'a-test-secret-that-is-long-enough-1234567890';

    private const string JWK = '{"kty":"RSA","d":"secret-exponent"}';


    public function testSealedValueRoundTripsAndHidesThePlaintext(): void
    {
        $cipher = $this->cipher(self::SECRET);
        $sealed = $cipher->seal(self::JWK, 'kid-1');

        $this->assertTrue(KeyMaterialCipher::isSealed($sealed));
        $this->assertStringNotContainsString('secret-exponent', $sealed);
        $this->assertSame(self::JWK, $cipher->open($sealed, 'kid-1'));
    }


    public function testSealingIsRandomised(): void
    {
        $cipher = $this->cipher(self::SECRET);

        $this->assertNotSame($cipher->seal(self::JWK, 'kid-1'), $cipher->seal(self::JWK, 'kid-1'));
    }


    public function testCiphertextIsBoundToItsKid(): void
    {
        $cipher = $this->cipher(self::SECRET);

        $this->expectException(RuntimeException::class);
        $cipher->open($cipher->seal(self::JWK, 'kid-1'), 'kid-2');
    }


    public function testTheWrongSecretCannotOpenIt(): void
    {
        $sealed = $this->cipher(self::SECRET)->seal(self::JWK, 'kid-1');

        $this->expectException(RuntimeException::class);
        $this->cipher(str_repeat('x', 40))->open($sealed, 'kid-1');
    }


    public function testTamperedCiphertextIsRejected(): void
    {
        $cipher = $this->cipher(self::SECRET);
        $sealed = $cipher->seal(self::JWK, 'kid-1');
        $raw    = (string) base64_decode(substr($sealed, strlen('enc:v1:')));
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);

        $this->expectException(RuntimeException::class);
        $cipher->open('enc:v1:' . base64_encode($raw), 'kid-1');
    }


    public function testWithoutASecretValuesStayPlainButSealedOnesCannotBeRead(): void
    {
        $plain = $this->cipher(null);
        $this->assertFalse($plain->isEnabled());
        $this->assertSame(self::JWK, $plain->seal(self::JWK, 'kid-1'));
        $this->assertSame(self::JWK, $plain->open(self::JWK, 'kid-1'));

        $this->expectException(RuntimeException::class);
        $plain->open($this->cipher(self::SECRET)->seal(self::JWK, 'kid-1'), 'kid-1');
    }


    public function testAShortSecretIsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->cipher('too-short');
    }


    public function testTheKeyStoreIsEncryptedAndStillSigns(): void
    {
        $config = $this->moduleConfig(['key_store_secret' => self::SECRET]);
        $kms    = new KeyManagementService($config, $this->pdo);
        $kid    = $kms->activeSigningContext()['kid'];

        $stored = (string) $this->pdo->query('SELECT private_jwk FROM oidanchor_federation_keys')->fetchColumn();
        $this->assertTrue(KeyMaterialCipher::isSealed($stored));

        $token = $this->keys($config)->signEntityStatement([
            'iss' => self::ENTITY_ID, 'sub' => self::ENTITY_ID, 'iat' => time(), 'exp' => time() + 60,
            'jwks' => $kms->publicJwks(),
        ]);
        $this->assertSame($kid, self::decodeJwt($token)['header']['kid']);
    }


    public function testPlaintextKeysAreEncryptedOnceASecretIsConfigured(): void
    {
        $kid = (new KeyManagementService($this->moduleConfig(), $this->pdo))->activeSigningContext()['kid'];
        $this->assertFalse(KeyMaterialCipher::isSealed($this->storedPrivateJwk()));

        $config = $this->moduleConfig(['key_store_secret' => self::SECRET]);
        $this->assertSame($kid, (new KeyManagementService($config, $this->pdo))->activeSigningContext()['kid']);
        $this->assertTrue(KeyMaterialCipher::isSealed($this->storedPrivateJwk()));
    }


    private function storedPrivateJwk(): string
    {
        return (string) $this->pdo->query('SELECT private_jwk FROM oidanchor_federation_keys')->fetchColumn();
    }


    private function cipher(?string $secret): KeyMaterialCipher
    {
        return KeyMaterialCipher::fromConfig($this->moduleConfig(['key_store_secret' => $secret]));
    }
}
