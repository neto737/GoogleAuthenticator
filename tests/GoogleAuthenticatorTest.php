<?php

use neto737\GoogleAuthenticator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(GoogleAuthenticator::class)]
#[UsesClass(GoogleAuthenticator::class)]
class GoogleAuthenticatorTest extends TestCase
{
    /**
     * @return array[] of parameters
     * Thanks to https://github.com/PHPGangsta/GoogleAuthenticator/pull/41
     */
    public static function paramsProvider(): array
    {
        return [
            [null, null, null, '200x200', 'M'],
            [-1, -1, null, '200x200', 'M'],
            [250, 250, 'L', '250x250', 'L'],
            [250, 250, 'M', '250x250', 'M'],
            [250, 250, 'Q', '250x250', 'Q'],
            [250, 250, 'H', '250x250', 'H'],
            [250, 250, 'Z', '250x250', 'M'],
        ];
    }

    /**
     * @return array[] of check triples
     */
    public static function codeProvider(): array
    {
        // Secret, unix-time, code
        return [
            ['SECRET', 0, '377331'],
            ['SECRET', 1385909245, '010454'],
            ['SECRET', 1378934578, '299040'],
        ];
    }

    public function testGenerator()
    {
        ob_start();
        $auth = new GoogleAuthenticator;
        try {
            $secret = $auth->createSecret();
        } catch (Exception $e) {
            echo $e->getMessage();
            $this->fail();
        }
        echo "Secret is: " . $secret . "\n\n";

        $qrCodeUrl = $auth->getQRCodeGoogleUrl($secret, 'Test@test.test', 'Company');
        echo "Google Charts URL for the QR-Code: " . $qrCodeUrl . "\n\n";

        $oneCode = $auth->getCode($secret);
        echo "Checking Code '$oneCode' and Secret '$secret':\n";

        ob_end_clean();

        $this->assertTrue($auth->verifyCode($secret, $oneCode, 2));
    }

    public function testConstructorException()
    {
        $this->expectException(ValueError::class);
        $auth = new GoogleAuthenticator(0);
        $secret = $auth->createSecret(0);
    }

    public function testCreateSecretTooLowSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new GoogleAuthenticator;
        $secret = $auth->createSecret(0);
    }

    public function testCreateSecretTooHighSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new GoogleAuthenticator;
        $secret = $auth->createSecret(99999);
    }

    public function testCreateSecretOnNull()
    {
        $auth = new GoogleAuthenticator(null);
        $this->assertEquals(6, $auth->getCodeLength());
        $this->assertEquals('sha256', $auth->getAlgorithm());

        $auth = new GoogleAuthenticator(6, null);
        $this->assertEquals(6, $auth->getCodeLength());
        $this->assertEquals('sha256', $auth->getAlgorithm());
    }


    public function testCreateSecretWithWrongHashFunction()
    {
        $this->expectException(ValueError::class);
        $auth = new GoogleAuthenticator(6, 'DOGGO');
    }

    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $auth = new GoogleAuthenticator;
        $secret = $auth->createSecret();

        $this->assertEquals(32, strlen($secret));
    }

    public function testCreateSecretLengthCanBeSpecified()
    {
        $auth = new GoogleAuthenticator;

        for ($secretLength = 16; $secretLength < 100; ++$secretLength) {
            $secret = $auth->createSecret($secretLength);

            $this->assertEquals(strlen($secret), $secretLength);
        }
    }

    #[DataProvider('codeProvider')]
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code)
    {
        $auth = new GoogleAuthenticator;

        $this->assertEquals($code, $auth->getCode($secret, $timeSlice));
    }

    public function testGetQRCodeGoogleUrlReturnsCorrectUrl()
    {
        $auth = new GoogleAuthenticator;

        $secret = 'SECRET';
        $name = 'Test';
        $url = $auth->getQRCodeGoogleUrl($secret, $name);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals('https', $urlParts['scheme']);
        $this->assertEquals('api.qrserver.com', $urlParts['host']);
        $this->assertEquals('/v1/create-qr-code/', $urlParts['path']);

        $expectedChl = 'otpauth://totp/' . $name . '?secret=' . $secret . '&algorithm=sha256';

        $this->assertEquals($queryStringArray['data'], $expectedChl);
    }

    public function testVerifyCode()
    {
        $auth = new GoogleAuthenticator;

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);

        $this->assertTrue($result);

        $code = 'INVALIDCODE';
        $result = $auth->verifyCode($secret, $code);

        $this->assertFalse($result);
    }

    public function testVerifyCodeWithLeadingZero()
    {
        $auth = new GoogleAuthenticator;

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);
        $this->assertTrue($result);

        $code = '0' . $code;
        $result = $auth->verifyCode($secret, $code);
        $this->assertFalse($result);
    }

    public function testVerifyCodeWithWrongCode()
    {
        $auth = new GoogleAuthenticator;

        $secret = 'SECRET';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    public function testEmptySecret()
    {
        $auth = new GoogleAuthenticator;

        $secret = '';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    public function testLongerUserKey()
    {
        $auth = new GoogleAuthenticator;

        $secret = '';
        $code = "00000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    #[DataProvider('paramsProvider')]
    public function testGetQRCodeGoogleUrlReturnsCorrectUrlWithOptionalParameters($width, $height, $ecc, $expectedSize, $expectedLevel)
    {
        $auth = new GoogleAuthenticator;

        $secret = 'SECRET';
        $name = 'Test';
        $url = $auth->getQRCodeGoogleUrl($secret, $name, null, [
            'width' => $width,
            'height' => $height,
            'ecc' => $ecc
        ]);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals($queryStringArray['size'], $expectedSize);
        $this->assertEquals($queryStringArray['ecc'], $expectedLevel);
    }
}
