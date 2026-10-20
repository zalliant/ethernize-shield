<?php

declare(strict_types=1);

namespace Ethernize\Shield\Csrf;

use Ethernize\Core\Session\SessionInterface;

/**
 * CSRF tokens bound to the session.
 *
 * The session holds one random secret. Each token given to a page is that secret XORed with a fresh
 * random mask (mask and result are sent together), so the token differs on every render and the
 * page cannot leak the secret through compression side channels. Verification unmasks it and compares
 * in constant time. A token from another session, or from before a login or logout, never verifies.
 */
final class CsrfTokens
{
    public const KEY = '_shield.csrf';
    public const FIELD = '_token';
    public const HEADER = 'X-CSRF-Token';

    private const BYTES = 32;

    public function __construct(private readonly SessionInterface $session)
    {
    }

    /** Replaces the session's secret: tokens issued before stop verifying. */
    public static function rotate(SessionInterface $session): void
    {
        $session->set(self::KEY, bin2hex(random_bytes(self::BYTES)));
    }

    /** A token for a form or a request header. Creates the session's secret on first use. */
    public function token(): string
    {
        $secret = $this->secret(true);
        $mask = random_bytes(self::BYTES);

        return rtrim(strtr(base64_encode($mask . ($secret ^ $mask)), '+/', '-_'), '=');
    }

    /** Verification never creates a secret: a session that never showed a token cannot pass. */
    public function verify(mixed $token): bool
    {
        $secret = $this->secret(false);

        if ($secret === null || !is_string($token) || strlen($token) !== 86 || preg_match('/^[A-Za-z0-9_-]+$/', $token) !== 1) {
            return false;
        }

        $raw = base64_decode(strtr($token, '-_', '+/'), true);

        if ($raw === false || strlen($raw) !== self::BYTES * 2) {
            return false;
        }

        $mask = substr($raw, 0, self::BYTES);

        return hash_equals($secret, substr($raw, self::BYTES) ^ $mask);
    }

    private function secret(bool $create): ?string
    {
        $stored = $this->session->get(self::KEY);

        if (is_string($stored) && preg_match('/^[a-f0-9]{64}$/', $stored) === 1) {
            return (string) hex2bin($stored);
        }

        if (!$create) {
            return null;
        }

        $secret = random_bytes(self::BYTES);
        $this->session->set(self::KEY, bin2hex($secret));

        return $secret;
    }
}
