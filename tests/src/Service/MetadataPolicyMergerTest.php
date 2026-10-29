<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidanchor\Service\MetadataPolicyMerger;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;

#[CoversClass(MetadataPolicyMerger::class)]
final class MetadataPolicyMergerTest extends TestCase
{
    public function testNothingToMergeYieldsNull(): void
    {
        $merger = new MetadataPolicyMerger();

        $this->assertNull($merger->merge(null, null));
        $this->assertNull($merger->merge([], []));
    }


    public function testASinglePolicyIsReturnedAsIs(): void
    {
        $policy = ['openid_relying_party' => ['grant_types' => ['subset_of' => ['authorization_code']]]];

        $this->assertSame($policy, (new MetadataPolicyMerger())->merge($policy, null));
        $this->assertSame($policy, (new MetadataPolicyMerger())->merge(null, $policy));
    }


    public function testFederationAndSubordinatePoliciesAreMerged(): void
    {
        $merged = (new MetadataPolicyMerger())->merge(
            ['openid_relying_party' => [
                'grant_types'   => ['subset_of' => ['authorization_code', 'refresh_token']],
                'contacts'      => ['add' => ['ops@ta.example.org']],
            ]],
            ['openid_relying_party' => [
                'grant_types'   => ['subset_of' => ['authorization_code']],
                'contacts'      => ['add' => ['ops@leaf.example.org']],
            ]],
        );

        $this->assertNotNull($merged);
        $rp = $merged['openid_relying_party'];
        $this->assertSame(['authorization_code'], array_values($rp['grant_types']['subset_of']));
        $this->assertEqualsCanonicalizing(['ops@ta.example.org', 'ops@leaf.example.org'], $rp['contacts']['add']);
        $this->assertArrayNotHasKey('openid_provider', $merged);
    }


    public function testIncompatiblePoliciesThrow(): void
    {
        $this->expectException(MetadataPolicyException::class);

        (new MetadataPolicyMerger())->merge(
            ['openid_relying_party' => ['token_endpoint_auth_method' => ['value' => 'private_key_jwt']]],
            ['openid_relying_party' => ['token_endpoint_auth_method' => ['value' => 'client_secret_basic']]],
        );
    }
}
