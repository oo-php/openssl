<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL\CSR;

use OOPHP\OpenSSL\ConfigSpec;
use OOPHP\OpenSSL\OpenSSLException;
use OOPHP\OpenSSL\OpenSSLResource;
use OOPHP\OpenSSL\Pair\PrivateKey;
use OOPHP\OpenSSL\Pair\PublicKey;
use OOPHP\OpenSSL\X509\X509Certificate;

/**
 * Class CertificateSigningRequest.
 */
final class CertificateSigningRequest extends OpenSSLResource
{
    /**
     * @param PrivateKey        $privateKey
     * @param DistinguishedName $dn
     * @param ConfigSpec|null   $spec
     *
     * @return static
     */
    public static function fromPrivateKey(PrivateKey $privateKey, DistinguishedName $dn, ConfigSpec $spec = null): self
    {
        $csr = openssl_csr_new(
            $dn->toArray(),
            $privateKey->resource,
            $spec !== null ? $spec->toArray() : []
        );
        if ($csr === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($csr);
    }

    /**
     * Signs the CSR generating a new X509 Certificate.
     *
     * @param PrivateKey           $privateKey
     * @param X509Certificate|null $ca
     * @param int                  $days
     *
     * @return X509Certificate
     */
    public function sign(PrivateKey $privateKey, X509Certificate $ca = null, int $days = 365): X509Certificate
    {
        return X509Certificate::fromCSR($this, $privateKey, $ca, $days);
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return new PublicKey(openssl_csr_get_public_key($this->resource));
    }

    /**
     * @return string
     */
    public function toPEM(): string
    {
        if (openssl_csr_export($this->resource, $out, false) === true) {
            return $out;
        }
        throw OpenSSLException::fromLastError();
    }

    /**
     * @param string $path
     */
    public function writeTo(string $path): void
    {
        if (file_put_contents($path, $this->toPEM()) === false) {
            throw new \RuntimeException('Could not write CRS to path');
        }
    }

    public function __destruct()
    {
    }
}
