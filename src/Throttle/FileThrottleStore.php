<?php

declare(strict_types=1);

namespace Ethernize\Shield\Throttle;

use Closure;
use RuntimeException;

/**
 * Counters as small JSON files named by a hash of the key. The increment runs under an exclusive
 * lock on a single lock file, so concurrent requests never read the same value twice.
 */
final class FileThrottleStore implements ThrottleStore
{
    /** @var Closure(): int */
    private readonly Closure $clock;

    /**
     * @param (Closure(): int)|null $clock current Unix time, replaceable for tests
     */
    public function __construct(private readonly string $directory, ?Closure $clock = null)
    {
        $this->clock = $clock ?? static fn (): int => time();
    }

    public function hit(string $key, int $seconds): int
    {
        return $this->locked(function () use ($key, $seconds): int {
            $now = ($this->clock)();
            $record = $this->read($key, $now);
            $count = ($record['n'] ?? 0) + 1;
            $expires = $record['x'] ?? $now + $seconds;

            $file = $this->file($key);
            $temporary = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';

            if (file_put_contents($temporary, json_encode(['n' => $count, 'x' => $expires], JSON_THROW_ON_ERROR)) === false || !rename($temporary, $file)) {
                @unlink($temporary);

                throw new RuntimeException('Could not write the throttle store.');
            }

            if (random_int(1, 200) === 1) {
                $this->collect($now);
            }

            return $count;
        });
    }

    public function attempts(string $key): int
    {
        return $this->read($key, ($this->clock)())['n'] ?? 0;
    }

    public function availableIn(string $key): int
    {
        $now = ($this->clock)();

        return max(0, ($this->read($key, $now)['x'] ?? $now) - $now);
    }

    public function forget(string $key): void
    {
        $this->locked(function () use ($key): void {
            @unlink($this->file($key));
        });
    }

    /**
     * @return array{n: int, x: int}|null null when absent, expired or unreadable
     */
    private function read(string $key, int $now): ?array
    {
        $file = $this->file($key);

        if (!is_file($file)) {
            return null;
        }

        $record = json_decode((string) @file_get_contents($file), true);

        return is_array($record) && is_int($record['n'] ?? null) && is_int($record['x'] ?? null) && $record['x'] > $now ? ['n' => $record['n'], 'x' => $record['x']] : null;
    }

    private function collect(int $now): void
    {
        foreach (glob($this->directory . '/*.throttle') ?: [] as $file) {
            $record = json_decode((string) @file_get_contents($file), true);

            if (!is_array($record) || ($record['x'] ?? 0) <= $now) {
                @unlink($file);
            }
        }
    }

    /**
     * @template T
     * @param Closure(): T $operation
     * @return T
     */
    private function locked(Closure $operation): mixed
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Could not create the throttle directory.');
        }

        $lock = fopen($this->directory . '/lock', 'c');

        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock the throttle store.');
        }

        try {
            return $operation();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function file(string $key): string
    {
        return $this->directory . '/' . hash('sha256', $key) . '.throttle';
    }
}
