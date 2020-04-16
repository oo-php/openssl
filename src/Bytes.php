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
 * Class Bytes.
 *
 * Utility class to work with signatures and encryption results.
 */
class Bytes
{
    /**
     * @var string
     */
    private $bytes;

    /**
     * @param int $length
     *
     * @return Bytes
     */
    public static function random(int $length): Bytes
    {
        try {
            return new self(random_bytes($length));
        } catch (\Exception $e) {
            throw new \RuntimeException('Not enough entropy');
        }
    }

    /**
     * @param string $base64
     *
     * @return Bytes
     */
    public static function fromBase64(string $base64): Bytes
    {
        $bin = base64_decode($base64, true);
        if (!is_string($bin)) {
            throw new \InvalidArgumentException('Not a base64 string');
        }

        return new self($bin);
    }

    /**
     * @param string $hex
     *
     * @return Bytes
     */
    public static function fromHex(string $hex): Bytes
    {
        $bin = @hex2bin($hex);
        if (!is_string($bin)) {
            throw new \InvalidArgumentException('Not an hexadecimal string');
        }

        return new self($bin);
    }

    /**
     * @param string $bytes
     *
     * @return Bytes
     */
    public static function fromRaw(string $bytes): Bytes
    {
        return new self($bytes);
    }

    /**
     * Bytes constructor.
     *
     * @param string $bytes
     */
    protected function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    public function toHex(): string
    {
        return bin2hex($this->bytes);
    }

    public function toBase64(): string
    {
        return base64_encode($this->bytes);
    }

    public function doesEqual(Bytes $bytes): bool
    {
        return $this->bytes === $bytes->bytes;
    }

    /**
     * @return int
     */
    public function getLength(): int
    {
        return strlen($this->bytes);
    }

    public function raw(): string
    {
        return $this->bytes;
    }
}
