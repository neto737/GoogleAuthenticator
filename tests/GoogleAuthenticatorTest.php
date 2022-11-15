<?php

use PHPUnit\Framework\TestCase;

class GoogleAuthenticatorTest extends TestCase
{
    /**
     * Authenticator class instance
     *
     * @var GoogleAuthenticator
     */
    protected $googleAuthenticator;

    protected function setUp(): void
    {
        $this->googleAuthenticator = new PHPGangsta_GoogleAuthenticator();
    }

    public function codeProvider(): array
    {
        // Secret, timeSlice, code, codeLength, algo
        return [
            ['SECRET', '0', '200470'],
            ['SECRET', '1385909245', '780018'],
            ['SECRET', '1378934578', '705013'],

            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '1', '94287082', 8, 'sha1'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '37037036', '07081804', 8, 'sha1'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '37037037', '14050471', 8, 'sha1'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '41152263', '89005924', 8, 'sha1'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '66666666', '69279037', 8, 'sha1'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '666666666', '65353130', 8, 'sha1'],

            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '1', '46119246', 8, 'sha256'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '37037036', '68084774', 8, 'sha256'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '37037037', '67062674', 8, 'sha256'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '41152263', '91819424', 8, 'sha256'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '66666666', '90698825', 8, 'sha256'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '666666666', '77737706', 8, 'sha256'],

            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '1', '90693936', 8, 'sha512'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '37037036', '25091201', 8, 'sha512'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '37037037', '99943326', 8, 'sha512'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '41152263', '93441116', 8, 'sha512'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '66666666', '38618901', 8, 'sha512'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', '666666666', '47863826', 8, 'sha512']
        ];
    }

    public function testItCanBeInstantiated(): void
    {
        $ga = new PHPGangsta_GoogleAuthenticator();

        $this->assertInstanceOf('PHPGangsta_GoogleAuthenticator', $ga);
    }

    public function testCreateSecretDefaultsToSixteenCharacters(): void
    {
        $ga = $this->googleAuthenticator;
        $secret = $ga->createSecret();

        $this->assertEquals(strlen($secret), 16);
    }

    public function testCreateSecretLengthCanBeSpecified(): void
    {
        $ga = $this->googleAuthenticator;

        for ($secretLength = 16; $secretLength < 100; ++$secretLength) {
            $secret = $ga->createSecret($secretLength);

            $this->assertEquals(strlen($secret), $secretLength);
        }
    }

    /**
     * @dataProvider codeProvider
     */
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code, $length = 6, $algo = 'sha1'): void
    {
        $this->googleAuthenticator->setCodeLength($length);
        $generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice, $algo);

        $this->assertEquals($code, $generatedCode);
    }

    public function testGetQRCodeGoogleUrlReturnsCorrectUrl(): void
    {
        $secret = 'SECRET';
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeGoogleUrl($name, $secret);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals($urlParts['scheme'], 'https');
        $this->assertEquals($urlParts['host'], 'api.qrserver.com');
        $this->assertEquals($urlParts['path'], '/v1/create-qr-code/');

        $expectedChl = 'otpauth://totp/' . $name . '?secret=' . $secret;

        $this->assertEquals($queryStringArray['data'], $expectedChl);
    }

    public function testVerifyCode(): void
    {
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertEquals(true, $result);

        $code = 'INVALIDCODE';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertEquals(false, $result);
    }

    public function testVerifyCodeWithLeadingZero(): void
    {
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        $code = '0' . $code;
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);
    }

    public function testSetCodeLength(): void
    {
        $result = $this->googleAuthenticator->setCodeLength(6);

        $this->assertInstanceOf('PHPGangsta_GoogleAuthenticator', $result);
    }

    public function testValidateCorrectCodeLength(): void
    {
        $secret = 'SECRET';
        $this->googleAuthenticator->setCodeLength(8);
        $this->assertEquals(true, $this->googleAuthenticator->verifyCode($secret, $this->googleAuthenticator->getCode($secret)));
    }
}
