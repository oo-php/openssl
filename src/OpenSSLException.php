<?php

declare(strict_types=1);

/*
 * This file is part of the OOPHP OpenSSL project.
 * (c) Matías Navarro-Carter <mnavarrocarter@gmail.com>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OOPHP\OpenSSL;

use RuntimeException;

/**
 * Class OpenSSLException.
 */
class OpenSSLException extends RuntimeException
{
    /**
     * @return OpenSSLException
     */
    public static function fromLastError(): OpenSSLException
    {
        return new self(openssl_error_string() ?: 'Unknown error');
    }
}
