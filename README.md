# Torugo PHP-JWT <!-- omit in toc -->

Simple PHP library to handle Json Web Tokens (JWT).

# Table of Contents <!-- omit in toc -->

- [Requirements](#requirements)
- [Installation via composer](#installation-via-composer)
- [Supported algorithms](#supported-algorithms)
- [Usage](#usage)
  - [Encoding](#encoding)
- [Decoding](#decoding)
  - [Validating the token](#validating-the-token)
  - [Getting the token payload without validating it](#getting-the-token-payload-without-validating-it)
- [Contribute](#contribute)
- [License](#license)

# Requirements

- PHP 8+
- PHP mbstring extension installed and loaded.
- PHP openssl extension installed and loaded.
- Composer 2+

# Installation via composer

```bash
composer require torugo/jwt
```
# Supported algorithms

For now only the algorithms listed below are supported:

| Algorithm | JWTALg enum     | Key                     |
| :-------: | --------------- | ----------------------- |
|   HS256   | `JWTAlg::HS256` | Symmetric key           |
|   HS384   | `JWTAlg::HS384` | Symmetric key           |
|   HS512   | `JWTAlg::HS512` | Symmetric key           |
|   RS256   | `JWTAlg::RS256` | Private/Public RSA keys |
|   RS384   | `JWTAlg::RS384` | Private/Public RSA keys |
|   RS512   | `JWTAlg::RS512` | Private/Public RSA keys |

# Usage

## Encoding

```php
use Torugo\JWT\JWT;
use Torugo\JWT\Enums\JwtAlg;

$key = "example_key_Jr6QWaxb7pgerDJgL";

$payload = [
    "sid" => "session_id",
    "uid" => "user_id",
    // ... more data
    "iat" => 1724972934, // if not present, this library adds automatically
    "nbf" => 1724000000, // if not present, this library adds automatically
    "ext" => 1724973234, // if not present, this library adds automatically
];

$jwt = JWT::encode($payload, $key, JWTAlg::HS256);

```

# Decoding

## Validating the token

The method `validate` checks the token signature and the time controls.  
Returns the payload content as a `key=>pair` array.

Throws:  
- `InvalidTokenException`: When the signature or structure is invalid.
- `ExpiredTokenException`: The token signature is valid, but the token time expired.
- `InvalidKeyException`: When the key type is invalid (not when the key is incorret).

```php
use Torugo\JWT\JWT;
use Torugo\JWT\Exceptions\ExpiredTokenException;
use Torugo\JWT\Exceptions\InvalidKeyException;
use Torugo\JWT\Exceptions\InvalidTokenException;

$key = "example_key_Jr6QWaxb7pgerDJgL";

try {
    $payload = JWT::validate($jwt, $key);
} catch (ExpiredTokenException $e) {
    // Handle exception
} catch (InvalidTokenException $e) {
    // Handle exception
} catch (InvalidKeyException $e) {
    // Handle exception
}
```

## Getting the token payload without validating it

Getting token payload without validation is insecure,
use this method at your own risk.

```php
$payload = JWT::decodePayload($jwt, $key);
```

You can use this method to refresh the token when the token expires.  
**Example**
```php
try {
    $payload = JWT::decodePayload($jwt, $key);
} catch (ExpiredTokenException $e) {
    // When using RS256, RS384 or RS512 you must also pass the privateKey
    // On HS algorithms it is not needed
    $token = JWT::refreshToken($token, $publicKey, $privatekey);
} catch (\Throwable $e) {
    // Handle exception
}
```

# Contribute

It is currently not open to contributions, I intend to make it available as soon as possible.

# License

This library is licensed under the MIT License - see the LICENSE file for details.
