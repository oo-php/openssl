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
 * Class OpenSSLResource.
 *
 * Defines an abstract resource that all OpenSSL resources extend.
 *
 * The purpose is to maintain encapsulation by making all resources share this
 * basic common scope, so the actual underlying OpenSSL resource streams can
 * be fetched from inside another resource.
 *
 * It also forces the implementation of the destruct method that should free
 * the relevant resource from memory.
 *
 * It also prevents cloning.
 */
abstract class OpenSSLResource
{
    /**
     * @var resource
     */
    protected $resource;

    /**
     * OpenSSLResource constructor.
     *
     * @param resource $resource
     */
    final protected function __construct($resource)
    {
        if (!is_resource($resource)) {
            throw new \InvalidArgumentException('$key must be a resource');
        }
        $this->resource = $resource;
    }

    final public function __clone()
    {
        throw new \RuntimeException('Cloning of openssl resources is not supported');
    }

    abstract public function __destruct();
}
