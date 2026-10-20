<?php

declare(strict_types=1);

namespace Ethernize\Shield\Throttle;

/**
 * Counters with an expiry, for login-attempt limiting. Implement it over any storage (a database,
 * a cache); it only needs an atomic increment. Keys are opaque, already hashed by the caller.
 * Every method may throw when the storage is unavailable: the login throttle then refuses logins
 * instead of letting them through unlimited (fail closed).
 */
interface ThrottleStore
{
    /**
     * Adds one to the counter and returns the new value. The counter starts at 1 and expires
     * $seconds after that first hit (fixed window); later hits do not extend it.
     */
    public function hit(string $key, int $seconds): int;

    /** The current value, 0 when absent or expired. */
    public function attempts(string $key): int;

    /** Seconds until the counter expires, 0 when absent. */
    public function availableIn(string $key): int;

    public function forget(string $key): void;
}
