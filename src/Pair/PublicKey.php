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
use OOPHP\OpenSSL\OpenSSLException;
use OOPHP\OpenSSL\OpenSSLResource;
use OOPHP\OpenSSL\X509\X509Certificate;

/**
 * Class PublicKey.
 */
final class PublicKey extends OpenSSLResource implements Verifier
{
    /**
     * @param string $pem
     *
     * @return static
     */
    public static function parse(string $pem): self
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw OpenSSLException::fromLastError();
        }

        return new self($key);
    }

    /**
     * @param string $data
     *
     * @return Bytes
     */
    public function encrypt(string $data): Bytes
    {
        if (openssl_public_encrypt($data, $encrypted, $this->resource) === false) {
            throw OpenSSLException::fromLastError();
        }

        return Bytes::fromRaw($encrypted);
    }

    /**
     * @param X509Certificate $cert
     *
     * @return bool
     */
    public function correspondsTo(X509Certificate $cert): bool
    {
        return openssl_x509_check_private_key($cert->resource, $this->resource);
    }

    /**
     * @param Bytes $bytes
     *
     * @return string
     */
    public function decrypt(Bytes $bytes): string
    {
        if (openssl_public_decrypt($bytes->raw(), $string, $this->resource) === false) {
            throw OpenSSLException::fromLastError();
        }

        return $string;
    }

    /**
     * @param string $data
     * @param Bytes  $signature
     * @param int    $algorithm
     *
     * @return bool
     */
    public function isSignatureValid(string $data, Bytes $signature, int $algorithm = OPENSSL_ALGO_SHA512): bool
    {
        $result = openssl_verify($data, $signature->raw(), $this->resource, $algorithm);
        if ($result === -1) {
            throw OpenSSLException::fromLastError();
        }

        return $result === 1;
    }

    /**
     * @return string
     */
    public function toPEM(): string
    {
        return openssl_pkey_get_details($this->resource)['key'];
    }

    /**
     * @param string $path
     */
    public function writeTo(string $path): void
    {
        if (file_put_contents($path, $this->toPEM()) === false) {
            throw new \RuntimeException('Could not write Public Key to path');
        }
    }

    public function __destruct()
    {
        openssl_pkey_free($this->resource);
    }
}
