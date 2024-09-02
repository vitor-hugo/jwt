<?php declare(strict_types=1);

namespace Tests;

use DomainException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use Throwable;
use Torugo\JWT\Enums\JWTAlg;
use Torugo\JWT\Exceptions\ExpiredTokenException;
use Torugo\JWT\Exceptions\InvalidKeyException;
use Torugo\JWT\Exceptions\InvalidTokenException;
use Torugo\JWT\JWT;
use Torugo\Util\TFile\TFile;

#[Group("JWT")]
#[TestDox("JWT unit tests")]
class JWTTest extends TestCase
{
    protected static string $symmetricKey;
    protected static string $privateRSAKey;
    protected static string $publicRSAKey;

    public static function setUpBeforeClass(): void
    {
        self::$symmetricKey = (new TFile(__DIR__ . "/keys/symmetric-key.key"))->getContent();
        self::$privateRSAKey = (new TFile(__DIR__ . "/keys/rsa-private.pem"))->getContent();
        self::$publicRSAKey = (new TFile(__DIR__ . "/keys/rsa-public.pem"))->getContent();
    }

    private function getRightEncodingKey(JWTAlg $alg): string
    {
        $a = substr($alg->value, 0, 2);
        if ($a === "hs") {
            return self::$symmetricKey;
        } else {
            return self::$privateRSAKey;
        }
    }

    private function getRightDecodingKey(JWTAlg $alg): string
    {
        $a = substr($alg->value, 0, 2);
        if ($a === "hs") {
            return self::$symmetricKey;
        } else {
            return self::$publicRSAKey;
        }
    }

    #[TestDox("Should generate a valid JWT")]
    public function testShouldEncodeArray(): array
    {
        $payload = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        $tokens = [];

        foreach (JWTAlg::cases() as $alg) {
            $jwt = JWT::encode($payload, $this->getRightEncodingKey($alg), $alg);
            // echo "\n\n$jwt";
            $this->assertIsString($jwt);
            $this->assertNotEmpty($jwt);
            $tokens[] = $jwt;
        }

        return $tokens;
    }


    #[TestDox("Should validate generated JWTs")]
    #[Depends("testShouldEncodeArray")]
    public function testShouldValidateGeneratedTokens(array $tokens)
    {
        $expected = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        foreach ($tokens as $jwt) {
            $header = JWT::decodeHeader($jwt);
            $key = $this->getRightDecodingKey($header["alg"]);
            $payload = JWT::validate($jwt, $key);

            $this->assertEquals($expected["sid"], $payload["sid"]);
            $this->assertEquals($expected["uid"], $payload["uid"]);
            $this->assertEquals($expected["user"], $payload["user"]);
            $this->assertEquals($expected["name"], $payload["name"]);
            $this->assertArrayHasKey("iat", $payload);
            $this->assertArrayHasKey("nbf", $payload);
            $this->assertArrayHasKey("exp", $payload);
        }
    }

    #[TestDox("Should throw InvalidTokenException when signature is invalid")]
    #[Depends("testShouldEncodeArray")]
    public function testShouldThrowOnInvalidSignatures(array $tokens)
    {
        foreach ($tokens as $jwt) {
            $header = JWT::decodeHeader($jwt);
            $key = $this->getRightDecodingKey($header["alg"]);
            $jwt = "{$jwt}XXX";

            try {
                JWT::validate($jwt, $key);
            } catch (Throwable $th) {
                $this->assertStringContainsString(
                    "InvalidTokenException",
                        $th::class
                );
            }
        }
    }


    #[TestDox("Should throw InvalidKeyException when key is empty")]
    public function testShouldThrowInvalidKeyExceptionWhenKeyIsEmtpy()
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage("JWT: Invalid symmetric key.");

        $payload = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        JWT::encode($payload, "", JWTAlg::HS256);
    }


    #[TestDox("Should throw InvalidKeyException when key is invalid")]
    public function testShouldThrowInvalidKeyExceptionWhenKeyIsInvalid()
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage("JWT: Invalid OpenSSL key.");

        $payload = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        JWT::encode($payload, "xyz", JWTAlg::RS256);
    }

    #[TestDox("Should throw DomainException on json_encode() function error")]
    public function testThrowExceptionOnJsonEncodeError()
    {
        $this->expectException(DomainException::class);
        $arr = ["\xB1\x31"];
        JWT::encode($arr, "QMO4Vt5SOKg9zmXrvzt2Ph4rJr6", JWTAlg::HS256);
    }

    #[TestDox("Should decode the token header")]
    public function testShouldDecodeTokenHeader()
    {
        $payload = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        foreach (JWTAlg::cases() as $alg) {
            $jwt = JWT::encode($payload, $this->getRightEncodingKey($alg), $alg);
            $header = JWT::decodeHeader($jwt);
            $this->assertEquals($alg, $header["alg"]);
            $this->assertEquals("JWT", $header["typ"]);
        }
    }

    #[TestDox("Should decode the token payload")]
    public function testShouldDecodeTokenPayload()
    {
        $payload = [
            "sid" => "987654321",
            "uid" => "123456789",
            "user" => "user@host.com",
            "name" => "User Something",
        ];

        foreach (JWTAlg::cases() as $alg) {
            $jwt = JWT::encode($payload, $this->getRightEncodingKey($alg), $alg);
            $decodedPayload = JWT::decodePayload($jwt);

            $this->assertEquals($payload["sid"], $decodedPayload["sid"]);
            $this->assertEquals($payload["uid"], $decodedPayload["uid"]);
            $this->assertEquals($payload["user"], $decodedPayload["user"]);
            $this->assertEquals($payload["name"], $decodedPayload["name"]);
            $this->assertArrayHasKey("iat", $decodedPayload);
            $this->assertArrayHasKey("nbf", $decodedPayload);
            $this->assertArrayHasKey("exp", $decodedPayload);
        }
    }

    #[TestDox("Should throw InvalidTokenException when token is invalid")]
    public function testThrowWhenTokenIsInvalid()
    {
        try {
            $invalidJWT = "x.y.z.w";
            JWT::decodePayload($invalidJWT);
        } catch (Throwable $th) {
            $this->assertEquals("Torugo\JWT\Exceptions\InvalidTokenException", $th::class);
        }

        try {
            $invalidJWT = "x..y";
            JWT::decodePayload($invalidJWT);
        } catch (Throwable $th) {
            $this->assertEquals("Torugo\JWT\Exceptions\InvalidTokenException", $th::class);
        }
    }

    #[TestDox("Should throw InvalidTokenException when payload is missing some keys")]
    public function testThrowWhenPayloadIsMissingSomeKeys()
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("JWT: Invalid token, element 'iat' is missing.");
        $invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiI5ODc2NTQzM";
        $invalid .= "jEiLCJ1aWQiOiIxMjM0NTY3ODkiLCJ1c2VyIjoidXNlckBob3N0LmNvbS";
        $invalid .= "IsIm5hbWUiOiJVc2VyIFNvbWV0aGluZyJ9.xFWSsaOT1x-gvZj1IJ7OOe";
        $invalid .= "iGs7Nldbjo46aUlClB6Qg";
        JWT::decodePayload($invalid);
    }

    #[TestDox("Should throw InvalidTokenException when algorithm is not supported")]
    public function testShouldThrowWhenAlgIsNotSupported()
    {
        $token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImM3YTIxNDAyMmVh";
        $token .= "M2MzOWEyOTIwMWE0Zjk3ODQzYjhkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiw";
        $token .= "ibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzI1MDI0NjQ1fQ.Fm61AV4WdBp";
        $token .= "5YpKMGdnD4nn0IxtAEXtBwH2YyFLJ_ZFdXDbzjUilnlGjaqdo5QhGlclkrH";
        $token .= "lAJFaqsL3iiehJPw";

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("JWT: The algorithm ES256 is not supported.");
        JWT::decodeHeader($token);
    }

    #[TestDox("Should throw InvalidTokenException when algorithm is not defined")]
    public function testShouldThrowWhenAlgIsNotDefined()
    {
        $token = "eyJ0eXAiOiJKV1QifQ.eyJzaWQiOiI5ODc2NTQzMjEiLCJ1aWQiOiIxMjM0N";
        $token .= "TY3ODkiLCJ1c2VyIjoidXNlckBob3N0LmNvbSIsIm5hbWUiOiJVc2VyIFNv";
        $token .= "bWV0aGluZyIsImlhdCI6MTcyNTAyNTA5MSwibmJmIjoxNzI1MDAsImV4cCI";
        $token .= "6MTcyNTAyNTM5MX0.pdbN7ul1YOv9B3O97L_jErJLySA3PdwajE7JJqWhYys";

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("JWT: Invalid token, unknown algorithm.");
        JWT::decodeHeader($token);
    }

    #[TestDox("Should throw DomainException on json_decode() function error")]
    public function testThrowOnJsonDecodeError()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage("JWT: Malformed UTF-8 characters, possibly incorrectly encoded");
        JWT::decodeHeader("sTE.sTE.sTE");
    }

    #[TestDox("Should throw ExpiredTokenException when token is expired")]
    public function testShouldThrowWhenExpired()
    {
        $timestamp = time();

        $payload = [
            "iat" => $timestamp - 500,
            "exp" => $timestamp - 400
        ];

        $key = $this->getRightDecodingKey(JWTAlg::HS256);
        $token = JWT::encode($payload, $key, JWTAlg::HS256);

        $this->expectException(ExpiredTokenException::class);
        JWT::validate($token, $key);
    }

    #[TestDox("Should throw InvalidTokenException 'iat' is invalid")]
    public function testShouldThrowWhenIssedAtIsInvalid()
    {
        $payload = [
            "iat" => time() + 1000,
        ];

        $key = $this->getRightDecodingKey(JWTAlg::HS256);
        $token = JWT::encode($payload, $key, JWTAlg::HS256);

        $this->expectException(InvalidTokenException::class);
        JWT::validate($token, $key);
    }

    #[TestDox("Should throw InvalidTokenException 'nbf' is invalid")]
    public function testShouldThrowWhenNotBeforeIsInvalid()
    {
        $payload = [
            "nbf" => time() + 1000,
        ];

        $key = $this->getRightDecodingKey(JWTAlg::HS256);
        $token = JWT::encode($payload, $key, JWTAlg::HS256);

        $this->expectException(InvalidTokenException::class);
        JWT::validate($token, $key);
    }
}
