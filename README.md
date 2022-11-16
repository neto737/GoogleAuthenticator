# Google Authenticator PHP class

* Copyright (c) 2012-2016, [http://www.phpgangsta.de](http://www.phpgangsta.de)
* Author: Michael Kliewe, [@PHPGangsta](http://twitter.com/PHPGangsta) and [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
* Licensed under the BSD License.

[![Latest Stable Version](https://poser.pugx.org/neto737/googleauthenticator/version?style=for-the-badge)](https://packagist.org/packages/neto737/googleauthenticator)
[![Total Downloads](https://poser.pugx.org/neto737/googleauthenticator/downloads?style=for-the-badge)](https://packagist.org/packages/neto737/googleauthenticator)
[![License](https://poser.pugx.org/neto737/googleauthenticator/license?style=for-the-badge)](https://packagist.org/packages/neto737/googleauthenticator)
[![PHP Version Require](https://poser.pugx.org/neto737/googleauthenticator/require/php?style=for-the-badge)](https://packagist.org/packages/neto737/googleauthenticator)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/neto737/GoogleAuthenticator/PHP%20Composer?logo=github&style=for-the-badge)](https://github.com/neto737/googleauthenticator)
[![Codecov branch](https://img.shields.io/codecov/c/gh/neto737/googleauthenticator/main?logo=codecov&style=for-the-badge&token=38KPL9BX5F)](https://app.codecov.io/gh/neto737/googleauthenticator)

This PHP class can be used to interact with the Google Authenticator mobile app for 2-factor-authentication. This class
can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret. It implements TOTP 
according to [RFC 6238](https://tools.ietf.org/html/rfc6238)

For a secure installation you have to make sure that used codes cannot be reused (replay-attack). You also need to
limit the number of verifications, to fight against brute-force attacks. For example you could limit the amount of
verifications to 10 tries within 10 minutes for one IP address (or IPv6 block). It depends on your environment.

## Installation

- Use [Composer](https://getcomposer.org/doc/01-basic-usage.md) to install the package

- From project root directory execute following

```shell
$ composer require neto737/GoogleAuthenticator
```

Or if put the following in your `composer.json`:

```json
"require": {
    "neto737/GoogleAuthenticator": "~2.0"
}
```

## Usage

See following example:

```php
require 'vendor/autoload.php';

$ga = new \neto737\GoogleAuthenticator;

$secret = $ga->createSecret();
echo "Secret is: " . $secret . PHP_EOL . PHP_EOL;

$qrCodeUrl = $ga->getQRCodeGoogleUrl('Blog', $secret);
echo "Google Charts URL for the QR-Code: ".$qrCodeUrl . PHP_EOL . PHP_EOL;

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret': ";

$checkResult = $ga->verifyCode($secret, $oneCode, 2); // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}
```
Running the script provides the following output:
```
Secret is: OQB6ZZGYHCPSX4AK

Google Charts URL for the QR-Code: https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/infoATphpgangsta.de%3Fsecret%3DOQB6ZZGYHCPSX4AK

Checking Code '848634' and Secret 'OQB6ZZGYHCPSX4AK': OK
```

## Notes

If you like this script or have some features to add: contact me, visit my blog, fork this project, send pull requests, you know how it works.
