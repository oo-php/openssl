<?php
declare(strict_types=1);

namespace OOPHP\OpenSSL\Tests;

use OOPHP\OpenSSL\CSR\DistinguishedName;
use OOPHP\OpenSSL\Pair\PrivateKey;
use PHPUnit\Framework\TestCase;

/**
 * Class PrivateKeyTest
 * @package OOPHP\OpenSSL\Tests
 */
class PrivateKeyTest extends TestCase
{
    public function testCanSign(): void
    {
        $dn = DistinguishedName::blank()
            ->withCountry('GB')
            ->withStateOrProvince('Co Londonderry')
            ->withLocality('Coleraine')
            ->withOrganization('Spatialest')
            ->withOrganizationalUnit('Development Team')
            ->withCommonName('Spatialest Ltd')
            ->withEmailAddress('contact@spatialest.com');

        $private = PrivateKey::generate();
        $private2 = PrivateKey::generate();

        $csr = $private->createCSR($dn);

        $cert = $csr->sign($private);
        $cert2 = $csr->sign($private2);

        $cert->toPEM();
        $cert2->toPEM();
    }
}
