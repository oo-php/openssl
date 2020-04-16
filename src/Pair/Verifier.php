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

/**
 * Interface Verifier.
 */
interface Verifier
{
    /**
     * @param string $data
     * @param Bytes  $signature
     * @param int    $algorithm
     *
     * @return bool
     */
    public function isSignatureValid(string $data, Bytes $signature, int $algorithm): bool;
}
