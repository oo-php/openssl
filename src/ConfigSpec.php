<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL;

/**
 * Class ConfigSpec.
 */
class ConfigSpec
{
    /**
     * @var array
     */
    private $config;

    /**
     * @return ConfigSpec
     */
    public static function default(): ConfigSpec
    {
        return new self([
            'digest_alg' => 'sha512',
            'x509_extensions' => null,
            'req_extensions' => null,
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'encrypt_key' => false,
            'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC,
            'curve_name' => null,
        ]);
    }

    /**
     * @param string $curveName
     *
     * @return ConfigSpec
     */
    public function withCurve(string $curveName): ConfigSpec
    {
        return $this->cloneWith('curve_name', $curveName);
    }

    /**
     * @param string $algorithm
     *
     * @return ConfigSpec
     */
    public function withDigestAlgorithm(string $algorithm): ConfigSpec
    {
        return $this->cloneWith('digest_alg', $algorithm);
    }

    /**
     * @return ConfigSpec
     */
    public function withRSAKeyType(): ConfigSpec
    {
        return $this->cloneWith('private_key_type', OPENSSL_KEYTYPE_RSA);
    }

    public function withECKeyType(): ConfigSpec
    {
        return $this->cloneWith('private_key_type', OPENSSL_KEYTYPE_EC);
    }

    public function withDCAKeyType(): ConfigSpec
    {
        return $this->cloneWith('private_key_type', OPENSSL_KEYTYPE_DSA);
    }

    public function withDHKeyType(): ConfigSpec
    {
        return $this->cloneWith('private_key_type', OPENSSL_KEYTYPE_DH);
    }

    public function withDuplicatedBits(): ConfigSpec
    {
        return $this->cloneWith('private_key_bits', $this->config['private_key_bits'] * 2);
    }

    public function withEncryptedKey(): ConfigSpec
    {
        return $this->cloneWith('encrypt_key', true);
    }

    public function withEncryptionCypher(int $cipher): ConfigSpec
    {
        return $this->cloneWith('encrypt_key_cipher', $cipher);
    }

    /**
     * @param string $key
     * @param $value
     *
     * @return ConfigSpec
     */
    protected function cloneWith(string $key, $value): ConfigSpec
    {
        $clone = clone $this;
        $clone->config[$key] = $value;

        return $clone;
    }

    /**
     * ConfigSpec constructor.
     *
     * @param array $config
     */
    protected function __construct(array $config)
    {
        $this->config = $config;
    }

    public function toArray(): array
    {
        return $this->config;
    }
}
