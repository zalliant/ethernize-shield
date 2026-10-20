<?php

declare(strict_types=1);

namespace Ethernize\Shield\Throttle;

use InvalidArgumentException;
use Throwable;

/**
 * Limits repeated failed logins, with three counters over one window:
 *
 *  - login + origin: `maxAttempts` tries from one address for one login. Charged before the password
 *    is checked, so parallel guesses cannot all slip through; cleared by a successful login;
 *  - origin: `maxPerOrigin` failures from one address across all logins (guessing many accounts);
 *  - login: `maxPerLogin` failures for one login across all addresses (a distributed attack). It is
 *    deliberately high, so a stranger cannot lock someone out of their own account with a few requests.
 *
 * Keys never depend on whether the account exists, so every answer is the same for known and unknown
 * logins. The login is normalized (case, spacing, width, invisible characters) so trivial variations
 * share one counter; only a hash of it is stored.
 *
 * If the store fails, the attempt is refused: an attacker must not be able to switch the protection
 * off by making its storage unavailable.
 */
final class LoginThrottle
{
    public function __construct(
        private readonly ThrottleStore $store,
        private readonly int $maxAttempts = 5,
        private readonly int $maxPerOrigin = 20,
        private readonly int $maxPerLogin = 50,
        private readonly int $decaySeconds = 900,
        private readonly bool $enabled = true,
    ) {
        if ($maxAttempts < 1 || $maxPerOrigin < 1 || $maxPerLogin < 1 || $decaySeconds < 1) {
            throw new InvalidArgumentException('Throttle limits and decay must be positive.');
        }
    }

    /**
     * Asks to try a login. Returns null when allowed (a slot is taken), or the number of seconds
     * to wait when refused.
     */
    public function begin(string $login, ?string $origin): ?int
    {
        if (!$this->enabled) {
            return null;
        }

        try {
            $pair = $this->pairKey($login, $origin);

            if ($this->store->hit($pair, $this->decaySeconds) > $this->maxAttempts) {
                return max(1, $this->store->availableIn($pair));
            }

            foreach ([[$this->originKey($origin), $this->maxPerOrigin], [$this->loginKey($login), $this->maxPerLogin]] as [$key, $limit]) {
                if ($this->store->attempts($key) >= $limit) {
                    return max(1, $this->store->availableIn($key));
                }
            }
        } catch (Throwable) {
            return $this->decaySeconds;
        }

        return null;
    }

    /** Whether a login would be refused right now, without taking a slot. */
    public function retryAfter(string $login, ?string $origin): ?int
    {
        if (!$this->enabled) {
            return null;
        }

        try {
            foreach ([[$this->pairKey($login, $origin), $this->maxAttempts + 1], [$this->originKey($origin), $this->maxPerOrigin], [$this->loginKey($login), $this->maxPerLogin]] as [$key, $limit]) {
                if ($this->store->attempts($key) >= $limit) {
                    return max(1, $this->store->availableIn($key));
                }
            }
        } catch (Throwable) {
            return $this->decaySeconds;
        }

        return null;
    }

    public function failed(string $login, ?string $origin): void
    {
        if (!$this->enabled) {
            return;
        }

        try {
            $this->store->hit($this->originKey($origin), $this->decaySeconds);
            $this->store->hit($this->loginKey($login), $this->decaySeconds);
        } catch (Throwable) {
            // The login already failed; nothing more to refuse.
        }
    }

    public function succeeded(string $login, ?string $origin): void
    {
        if (!$this->enabled) {
            return;
        }

        try {
            $this->store->forget($this->pairKey($login, $origin));
        } catch (Throwable) {
            // Harmless: the counter simply expires.
        }
    }

    /** The form of a login that counters are keyed by. */
    public static function normalize(string $login): string
    {
        $text = trim($login);

        if (class_exists(\Normalizer::class)) {
            $text = \Normalizer::normalize($text, \Normalizer::FORM_KC) ?: $text;
        }

        // Full-width letters and digits become ASCII; invisible characters vanish; spacing collapses.
        $text = mb_convert_kana($text, 'as', 'UTF-8');
        $text = preg_replace('/[\p{Cc}\p{Cf}]+/u', '', $text) ?? $text;
        $text = preg_replace('/\p{Z}+/u', ' ', $text) ?? $text;

        return mb_strtolower(trim($text), 'UTF-8');
    }

    private function pairKey(string $login, ?string $origin): string
    {
        return 'pair:' . hash('sha256', self::normalize($login) . "\0" . ($origin ?? 'unknown'));
    }

    private function loginKey(string $login): string
    {
        return 'login:' . hash('sha256', self::normalize($login));
    }

    private function originKey(?string $origin): string
    {
        return 'origin:' . hash('sha256', $origin ?? 'unknown');
    }
}
