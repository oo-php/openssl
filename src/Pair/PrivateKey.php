<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL\Pair;

use OOPHP\OpenSSL\Bytes;
use OOPHP\OpenSSL\ConfigSpec;
use OOPHP\OpenSSL\CSR\CertificateSigningRequest;
use OOPHP\OpenSSL\CSR\DistinguishedName;
use OOPHP\OpenSSL\OpenSSLException;
use OOPHP\OpenSSL\OpenSSLResource;

/**
 * Class PrivateKey.
 */
final class PrivateKey extends OpenSSLResource implements Signer
{
    /**
     * @param string $keyFile
     * @param string $passphrase
     *
     * @return static
     */
    public static function fromFile(string $keyFile, string $passphrase = ''): self
    {
        if (!is_file($keyFile) || !is_readable($keyFile)) {
            throw new \InvalidArgumentException(sprintf('OpenSSLResource file %s does not exist or is not readable', $keyFile));
        }

        return self::parse(file_get_contents($keyFile), $passphrase);
    }

    /**
     * @param string $pem
     * @param string $passphrase
     *
     * @return static
     */
    public static function parse(string $pem, string $passphrase = ''): self
    {
        $key = openssl_pkey_get_private($pem, $passphrase);
        if ($key === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($key);
    }

    /**
     * @param ConfigSpec|null $config
     *
     * @return static
     */
    public static function generate(ConfigSpec $config = null): self
    {
        $key = openssl_pkey_new($config !== null ? $config->toArray() : []);
        if ($key === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($key);
    }

    /**
     * @param string|null     $passphrase
     * @param ConfigSpec|null $config
     *
     * @return string
     */
    public function toPEM(string $passphrase = null, ConfigSpec $config = null): string
    {
        if (openssl_pkey_export($this->resource, $out, $passphrase, $config !== null ? $config->toArray() : []) === false) {
            throw OpenSSLException::fromLastError();
        }

        return $out;
    }

    /**
     * @param string      $path
     * @param string|null $passphrase
     */
    public function writeTo(string $path, string $passphrase = null): void
    {
        if (file_put_contents($path, $this->toPEM($passphrase)) === false) {
            throw new \RuntimeException('Could not write Private Key to path');
        }
    }

    /**
     * @param string $data
     * @param int    $algorithm
     *
     * @return Bytes
     */
    public function sign(string $data, int $algorithm = OPENSSL_ALGO_SHA512): Bytes
    {
        if (openssl_sign($data, $signature, $this->resource, $algorithm) === false) {
            throw OpenSSLException::fromLastError();
        }

        return Bytes::fromRaw($signature);
    }

    /**
     * @param string $data
     *
     * @return Bytes
     */
    public function encrypt(string $data): Bytes
    {
        if (openssl_private_encrypt($data, $encrypted, $this->resource) === false) {
            throw OpenSSLException::fromLastError();
        }

        return Bytes::fromRaw($encrypted);
    }

    /**
     * @param Bytes $bytes
     *
     * @return string
     */
    public function decrypt(Bytes $bytes): string
    {
        if (openssl_private_decrypt($bytes->raw(), $string, $this->resource) === false) {
            throw OpenSSLException::fromLastError();
        }

        return $string;
    }

    /**
     * Creates a Certificate Signing Request.
     *
     * @param DistinguishedName $dn
     * @param ConfigSpec|null   $spec
     *
     * @return CertificateSigningRequest
     */
    public function createCSR(DistinguishedName $dn, ConfigSpec $spec = null): CertificateSigningRequest
    {
        return CertificateSigningRequest::fromPrivateKey($this, $dn, $spec);
    }

    /**
     * Gets the public key from the CSR.
     *
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return PublicKey::parse(openssl_pkey_get_details($this->resource)['key']);
    }

    public function __destruct()
    {
        openssl_pkey_free($this->resource);
    }
}
