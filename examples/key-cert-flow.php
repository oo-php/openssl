<?php

require_once __DIR__ . '/../vendor/autoload.php';

use OOPHP\OpenSSL\CSR\DistinguishedName;
use OOPHP\OpenSSL\Pair\PrivateKey;

// You can generate a new private key very easily. By default it takes your php
// openssl configuration. You can pass an optional argument to override the defaults.
$private = PrivateKey::generate();

// Then you can write the public key in pem format to the filesystem
$private->writeTo('name.key', 'passphrase'); // Passphrase is optional.

// Or you can get the public part and write it too
$private->getPublicKey()->writeTo('name.pub');

// You can encrypt any piece of data with the private key
$bytes = $private->encrypt('this-is-some-data');

// You can cast those bytes to convenient encodings
$bytes->toHex();
$bytes->toBase64();
// Or simply have them raw
$bytes->raw();

// You can decrypt back with the public part
$data = $private->getPublicKey()->decrypt($bytes);

// You can sign any piece of information too
$signature = $private->sign('some-public-info');

// And this signature is also a Bytes instance
$signature->toBase64();

// But probably the most cool thing is that you can create Certificate Signing Requests (CSR)

// For that we need some optional data first
$dn = DistinguishedName::blank()
    ->withCountry('GB')
    ->withLocality('Coleraine')
    ->withCommonName('Matías Navarro');

// We create the CRS using our Private Key
$csr = $private->createCSR($dn);

// The CSR can also be written to the filesystem
$csr->writeTo('name.csr');

// But what we really want is to create a cert out of it. In this case, will be
// self-signed valid for five years
$cert = $csr->sign($private, null, 365*5);

// And we can also save this certificate
$cert->writeTo('name.crt');

// Oh, how I love nice apis!