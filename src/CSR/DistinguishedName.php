<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL\CSR;

/**
 * Class DistinguishedName.
 */
class DistinguishedName
{
    /**
     * @var array
     */
    protected $dn;

    /**
     * @return DistinguishedName
     */
    public static function blank(): DistinguishedName
    {
        return new self([]);
    }

    /**
     * DistinguishedName constructor.
     *
     * @param array $dn
     */
    protected function __construct(array $dn)
    {
        $this->dn = $dn;
    }

    public function withCountry(string $country): DistinguishedName
    {
        return $this->cloneWith('countryName', $country);
    }

    public function withStateOrProvince(string $stateOrProvince): DistinguishedName
    {
        return $this->cloneWith('stateOrProvinceName', $stateOrProvince);
    }

    public function withLocality(string $locality): DistinguishedName
    {
        return $this->cloneWith('localityName', $locality);
    }

    public function withOrganization(string $organization): DistinguishedName
    {
        return $this->cloneWith('organizationName', $organization);
    }

    public function withOrganizationalUnit(string $unit): DistinguishedName
    {
        return $this->cloneWith('organizationalUnitName', $unit);
    }

    public function withCommonName(string $commonName): DistinguishedName
    {
        return $this->cloneWith('commonName', $commonName);
    }

    public function withEmailAddress(string $email): DistinguishedName
    {
        return $this->cloneWith('emailAddress', $email);
    }

    protected function cloneWith(string $key, $value): DistinguishedName
    {
        $clone = clone $this;
        $clone->dn[$key] = $value;

        return $clone;
    }

    public function toArray(): array
    {
        return $this->dn;
    }
}
