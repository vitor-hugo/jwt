<?php declare(strict_types=1);

namespace Torugo\JWT\Enums;

/**
 * Supported cipher algorithms
 */
enum JWTAlg: string
{
    case HS256 = "HS256";
    case HS384 = "HS384";
    case HS512 = "HS512";
    case RS256 = "RS256";
    case RS384 = "RS384";
    case RS512 = "RS512";
}
