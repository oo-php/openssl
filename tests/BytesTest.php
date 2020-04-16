<?php
declare(strict_types=1);

namespace OOPHP\OpenSSL\Tests;

use OOPHP\OpenSSL\Bytes;
use PHPUnit\Framework\TestCase;

class BytesTest extends TestCase
{

    public function testHex(): void
    {
        $hex = Bytes::random(8)->toHex();
        $bytes = Bytes::fromHex($hex);
        $this->assertEquals($hex, $bytes->toHex());

        $this->expectException(\InvalidArgumentException::class);
        Bytes::fromHex('332kf325232');
    }

    public function testBase64(): void
    {
        $base64 = Bytes::random(8)->toBase64();
        $bytes = Bytes::fromBase64($base64);
        $this->assertEquals($base64, $bytes->toBase64());

        $this->expectException(\InvalidArgumentException::class);
        Bytes::fromBase64('332kf325232@||q');
    }
}
