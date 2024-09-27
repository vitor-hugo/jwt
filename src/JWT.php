<?php declare(strict_types=1);

namespace Torugo\JWT;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Torugo\JWT\Enums\JWTAlg;
use Torugo\JWT\Exceptions\EncodingException;
use Torugo\JWT\Exceptions\ExpiredTokenException;
use Torugo\JWT\Exceptions\InvalidKeyException;
use Torugo\JWT\Exceptions\InvalidTokenException;
use Torugo\Util\TBase64\TBase64;

final class JWT
{
    private const SUPPORTED_ALGS = [
        "HS256" => ["hash_hmac", "sha256"],
        "HS384" => ["hash_hmac", "sha384"],
        "HS512" => ["hash_hmac", "sha512"],
        "RS256" => ["openssl", "sha256"],
        "RS384" => ["openssl", "sha384"],
        "RS512" => ["openssl", "sha512"],
    ];

    /**
     * Time in seconds to consider the token expired. Default 300 seconds (5min).
     * @var int
     */
    public static int $expirationTime = 300;

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * Default 3 seconds (3).
     * @var int
     */
    public static int $notBeforeLeeway = 3;

    /**
     * Generates a Json Web Token
     * @param array $payload Main token content
     * @param string|array|OpenSSLAsymmetricKey|OpenSSLCertificate $privateKey $key
     * @param JWTAlg $alg Hashing algorithm
     * @return string A Json Web Token
     * @throws InvalidKeyException|EncodingException
     */
    public static function encode(
        array $payload,
        mixed $key,
        JWTAlg $alg
    ): string {
        $header = self::encodeHeader($alg);
        $payload = self::encodePayload($payload);
        $signature = self::sign($header, $payload, $alg, $key);
        return "$header.$payload.$signature";
    }

    /**
     * Encodes the jwt header
     * @throws EncodingException When arrayToBase64() fails
     */
    private static function encodeHeader(JWTAlg $alg): string
    {
        $header = [
            "alg" => $alg->value,
            "typ" => "JWT"
        ];

        return self::arrayToBase64($header);
    }

    /**
     * Takes an array and encodes to json and then to a base64 url safe string
     * @param array $data Array to be encoded
     * @return string Base64 url safe string
     * @throws EncodingException When 'json_encode' function returns an error
     */
    private static function arrayToBase64(array $data): string
    {
        $json = @json_encode(
            $data,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        if ($errno = json_last_error()) {
            self::handleJsonError($errno);
        }

        return TBase64::encode($json);
    }

    /**
     * Encodes the payload inserting time controllers if not present
     * @param array $payload JWT main content
     * @return string
     * @throws EncodingException When arrayToBase64() fails
     */
    private static function encodePayload(array $payload): string
    {

        if (!array_key_exists("iat", $payload)) {
            $timestamp = time();
            $payload["iat"] = $timestamp;
        }

        if (!array_key_exists("nbf", $payload)) {
            $payload["nbf"] = $payload["iat"] + self::$notBeforeLeeway;
        }

        if (!array_key_exists("exp", $payload)) {
            $payload["exp"] = $payload["iat"] + self::$expirationTime;
        }

        return self::arrayToBase64($payload);
    }

    /**
     * Handles json_encode and json_decode errors
     * @param int $errno Error number from json_last_error()
     * @return void
     * @throws EncodingException
     */
    private static function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => "The maximum stack depth has been exceeded",
            JSON_ERROR_STATE_MISMATCH => "Invalid or malformed JSON",
            JSON_ERROR_CTRL_CHAR => "Control character error, possibly incorrectly encoded",
            JSON_ERROR_SYNTAX => "Syntax error, malformed JSON",
            JSON_ERROR_UTF8 => "Malformed UTF-8 characters, possibly incorrectly encoded",
        ];

        $message = $messages[$errno] ?? "unknown json error - $errno.";

        throw new EncodingException("JWT: $message");
    }

    /**
     * Signs the token using the correct hash function
     * @param string $encodedHeader
     * @param string $encodedPayload
     * @param JWTAlg $alg
     * @param mixed $key
     * @return string
     * @throws InvalidKeyException
     */
    private static function sign(
        string $encodedHeader,
        string $encodedPayload,
        JWTAlg $alg,
        mixed $key
    ): string {
        [$method, $alg] = self::SUPPORTED_ALGS[$alg->value];

        $baseToken = "$encodedHeader.$encodedPayload";

        return match ($method) {
            'hash_hmac' => self::signWithHashHmac($baseToken, $alg, $key),
            default => self::signWithOpenSSL($baseToken, $alg, $key),
        };
    }

    /**
     * Generates the token signature using the native PHP 'hash_hmac' function
     * @param string $content Content do be signed
     * @param string $algo Hashing algorithm
     * @param string $key Secret key
     * @return string
     * @throws InvalidKeyException
     */
    private static function signWithHashHmac(
        string $content,
        string $algo,
        string $key
    ): string {
        $key = trim($key);

        if (empty($key)) {
            throw new InvalidKeyException("JWT: Invalid symmetric key.");
        }

        $signature = hash_hmac($algo, $content, $key, true);
        return TBase64::encode($signature);
    }

    /**
     * Generates the token signature using native PHP 'openssl_sign' function
     * @param string $content Content to be signed
     * @param string $algorithm Hashing algorithm
     * @param array|OpenSSLAsymmetricKey|OpenSSLCertificate|string $privateKey Private secret key
     * @return string
     * @throws InvalidKeyException
     * @throws EncodingException
     */
    private static function signWithOpenSSL(
        string $content,
        string $algorithm,
        array|OpenSSLAsymmetricKey|OpenSSLCertificate|string $privateKey
    ): string {
        if (!is_resource($privateKey) && !openssl_pkey_get_private($privateKey)) {
            throw new InvalidKeyException("JWT: Invalid OpenSSL key.");
        }

        $signature = "";
        $isValid = openssl_sign($content, $signature, $privateKey, $algorithm);
        if (!$isValid) {
            throw new EncodingException("JWT: Unable to sign the data with OpenSSL.");
        }

        return TBase64::encode($signature);
    }

    /**
     * Validates the token, checking the signature and time controls
     * @param string $token Valid json web token
     * @param string $key Symmetric/Public Key
     * @return array
     * @throws ExpiredTokenException
     * @throws InvalidTokenException
     */
    public static function validate(string $token, string $key): array
    {
        $header = self::decodeHeader($token);
        $payload = self::decodePayload($token);
        self::validateSignature($token, $key, $header["alg"]);
        self::validatePayload($payload);

        return $payload;
    }

    /**
     * Decodes and validates the algorithm
     * @param string $token
     * @return array
     * @throws InvalidTokenException
     */
    public static function decodeHeader(string $token): array
    {
        $encodedHeader = self::extractTokenParts($token)[0];
        $header = self::decodeData($encodedHeader);

        if (!array_key_exists("alg", $header)) {
            throw new InvalidTokenException("JWT: Invalid token, unknown algorithm.");
        }

        $alg = JWTAlg::tryFrom($header["alg"]);

        if ($alg == null) {
            throw new InvalidTokenException("JWT: The algorithm {$header['alg']} is not supported.");
        }

        $header["alg"] = $alg;

        return $header;
    }

    /**
     * Decodes and checks if the time controls exists
     * @param string $token
     * @return array
     * @throws InvalidTokenException
     */
    public static function decodePayload(string $token): array
    {
        $encodedPayload = self::extractTokenParts($token)[1];
        $payload = self::decodeData($encodedPayload);

        $expectedKeys = ["iat", "nbf", "exp"];
        foreach ($expectedKeys as $key) {
            if (!array_key_exists($key, $payload)) {
                throw new InvalidTokenException("JWT: Invalid token, element '$key' is missing.");
            }
        }

        return $payload;
    }

    /**
     * Returns the token splitted in three parts [header, payload, signature]
     * @param string $token
     * @return array
     * @throws InvalidTokenException when token structure is invalid
     */
    private static function extractTokenParts(string $token): array
    {
        $parts = @explode(".", $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException("JWT: Invalid token string.");
        }

        foreach ($parts as $part) {
            if (empty($part)) {
                throw new InvalidTokenException("JWT: One or more parts of the token are invalid.");
            }
        }

        return $parts;
    }

    /**
     * Decodes the token header or payload
     * @param string $encoded Encoded header or payload
     * @return array
     */
    private static function decodeData(string $encoded): array
    {
        $json = TBase64::decode($encoded);
        $arr = @json_decode($json, true);

        if ($errno = json_last_error()) {
            self::handleJsonError($errno);
        }

        return $arr;
    }

    /**
     * Validates the token signature
     * @param string $token Valid Json Web Token
     * @param mixed $key Symmetric or Public key
     * @param JWTAlg $alg Algorithm used to sign
     * @return void
     * @throws InvalidTokenException|InvalidKeyException
     */
    private static function validateSignature(
        string $token,
        mixed $key,
        JWTAlg $alg
    ): void {
        [$method, $algo] = self::SUPPORTED_ALGS[$alg->value];

        switch ($method) {
            case 'hash_hmac':
                self::validateHashHmacSign($token, $algo, $key);
                break;

            case 'openssl':
            default:
                self::validateOpenSSLSign($token, $algo, $key);
                break;
        }
    }

    /**
     * Validastes tokens that were signed with 'hash_hmac' function
     * @param string $token Valid Json Web Token
     * @param string $algo Algorithm used to sign
     * @param string $key Symmetric Key
     * @return void
     * @throws InvalidTokenException|InvalidKeyException
     */
    private static function validateHashHmacSign(
        string $token,
        string $algo,
        string $key
    ): void {
        $parts = self::extractTokenParts($token);
        $baseToken = "$parts[0].$parts[1]";
        $signature = $parts[2];
        $hash = self::signWithHashHmac($baseToken, $algo, $key);

        if (!hash_equals($signature, $hash)) {
            throw new InvalidTokenException("JWT: Invalid json web token.");
        }
    }

    /**
     * Validastes tokens that were signed with 'openssl_sign' function
     * @param string $token Valid Json Web Token
     * @param string $algo Algorithm used to sign
     * @param string $key Public Key
     * @return void
     * @throws InvalidTokenException
     */
    private static function validateOpenSSLSign(
        string $token,
        string $algo,
        string $key
    ): void {
        $parts = self::extractTokenParts($token);
        $baseToken = "$parts[0].$parts[1]";
        $signature = TBase64::decode($parts[2]);
        $isValid = openssl_verify($baseToken, $signature, $key, $algo);

        if ($isValid <= 0 || $isValid === false) {
            throw new InvalidTokenException("JWT: Invalid json web token.");
        }
    }

    /**
     * Validates the time controls present on the payload;
     * @param array $payload
     * @return void
     * @throws ExpiredTokenException|InvalidTokenException
     */
    private static function validatePayload(array $payload): void
    {
        $iat = $payload["iat"];
        $nbf = $payload["nbf"];
        $exp = $payload["exp"];

        $timestamp = time();

        if ($nbf > $timestamp || $iat > $timestamp) {
            throw new InvalidTokenException("JWT: Invalid json web token.");
        }

        if ($exp < $timestamp) {
            throw new ExpiredTokenException("JWT: Session expired");
        }
    }

    /**
     * Renews the token expiration time. Before refreshing this method validates the token signature.
     * @param string $token
     * @param string|array|OpenSSLAsymmetricKey|OpenSSLCertificate $publicKey Symmetric/Public key
     * @param string|array|OpenSSLAsymmetricKey|OpenSSLCertificate $privateKey Used only with `RS###` algorithms
     * @return string
     * @throws InvalidTokenException
     */
    public static function refresh(
        string $token,
        mixed $publicKey,
        mixed $privateKey = ""
    ): string {
        try {
            $header = self::decodeHeader($token);
            self::validateSignature($token, $publicKey, $header["alg"]);
        } catch (\Throwable $th) {
            throw new InvalidTokenException(
                "JWT: Could not refresh the token because it is invalid."
            );
        }

        $payload = self::decodePayload($token);
        $timeToExpire = $payload["exp"] - $payload["iat"];
        $payload["exp"] = time() + $timeToExpire;


        [$method, $_] = self::SUPPORTED_ALGS[$header["alg"]->value];

        return match ($method) {
            "hash_hmac" => self::encode($payload, $publicKey, $header["alg"]),
            default => self::encode($payload, $privateKey, $header["alg"]),
        };
    }
}
