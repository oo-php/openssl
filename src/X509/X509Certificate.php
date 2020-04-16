<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL\X509;

use OOPHP\OpenSSL\CSR\CertificateSigningRequest;
use OOPHP\OpenSSL\OpenSSLException;
use OOPHP\OpenSSL\OpenSSLResource;
use OOPHP\OpenSSL\Pair\PrivateKey;

/**
 * Class X509Certificate.
 */
final class X509Certificate extends OpenSSLResource
{
    /**
     * @param string $keyFile
     *
     * @return static
     */
    public static function fromFile(string $keyFile): self
    {
        if (!is_file($keyFile) || !is_readable($keyFile)) {
            throw new \InvalidArgumentException(sprintf('OpenSSLResource file %s does not exist or is not readable', $keyFile));
        }

        return self::parse(file_get_contents($keyFile));
    }

    /**
     * @param string $pem
     *
     * @return static
     */
    public static function parse(string $pem): self
    {
        $key = openssl_x509_read($pem);
        if ($key === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($key);
    }

    /**
     * @param CertificateSigningRequest $csr
     * @param PrivateKey                $privateKey
     * @param X509Certificate|null      $ca
     * @param int                       $days
     *
     * @return static
     */
    public static function fromCSR(CertificateSigningRequest $csr, PrivateKey $privateKey, X509Certificate $ca = null, int $days = 365): self
    {
        $resource = openssl_csr_sign($csr->resource,
            $ca !== null ? $ca->resource : null,
            $privateKey->resource,
            $days
        );
        if ($resource === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($resource);
    }

    /**
     * @return array
     */
    public function getDetails(): array
    {
        return openssl_x509_parse($this->resource);
    }

    public function toPEM(): string
    {
        if (openssl_x509_export($this->resource, $out) === true) {
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
            throw new \RuntimeException('Could not write X509 Certificate to path');
        }
    }

    public function __destruct()
    {
        openssl_x509_free($this->resource);
    }
}
