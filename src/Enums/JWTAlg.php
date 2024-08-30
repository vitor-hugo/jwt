<?php declare(strict_types=1);

namespace Torugo\JWT\Enums;

/**
 * Supported cipher algorithms
 */
enum JWTAlg: string
{
    case HS256 = "hs256";
    case HS384 = "hs384";
    case HS512 = "hs512";
    case RS256 = "rs256";
    case RS384 = "rs384";
    case RS512 = "rs512";
}
