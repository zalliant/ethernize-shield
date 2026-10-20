<?php

declare(strict_types=1);

namespace Ethernize\Shield\Session;

use RuntimeException;

/**
 * Sessions as JSON files. The file name is a hash of the session id, so listing the folder
 * reveals nothing that can be used as a cookie. Files are replaced atomically, and the
 * compare-and-set of write() and delete() runs under a short exclusive lock (one of 16 lock
 * files, chosen by the id), held only for the duration of the check and the write.
 */
final class FileSessionStore implements SessionStore
{
    public function __construct(private readonly string $directory)
    {
    }

    public function read(string $id): ?array
    {
        $file = $this->file($id);

        if (!is_file($file)) {
            return null;
        }

        $record = json_decode((string) @file_get_contents($file), true);

        if (
            !is_array($record)
            || !is_int($record['c'] ?? null)
            || !is_int($record['a'] ?? null)
            || !is_int($record['v'] ?? null)
            || !is_array($record['d'] ?? null)
        ) {
            @unlink($file);

            return null;
        }

        return ['data' => $record['d'], 'created' => $record['c'], 'active' => $record['a'], 'version' => $record['v']];
    }

    public function write(string $id, array $data, int $created, int $active, ?int $expectedVersion = null): bool
    {
        return $this->locked($id, function () use ($id, $data, $created, $active, $expectedVersion): bool {
            $current = $this->read($id);

            if ($expectedVersion === null ? $current !== null : ($current === null || $current['version'] !== $expectedVersion)) {
                return false;
            }

            $file = $this->file($id);
            $temporary = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            $json = json_encode(['c' => $created, 'a' => $active, 'v' => ($expectedVersion ?? 0) + 1, 'd' => $data], JSON_THROW_ON_ERROR);

            if (file_put_contents($temporary, $json) === false || !rename($temporary, $file)) {
                @unlink($temporary);

                throw new RuntimeException('Could not write the session.');
            }

            return true;
        });
    }

    public function delete(string $id, ?int $expectedVersion = null): bool
    {
        return $this->locked($id, function () use ($id, $expectedVersion): bool {
            $current = $this->read($id);

            if ($current === null || ($expectedVersion !== null && $current['version'] !== $expectedVersion)) {
                return false;
            }

            return @unlink($this->file($id));
        });
    }

    public function collect(int $olderThan): void
    {
        foreach (glob($this->directory . '/*.session') ?: [] as $file) {
            if (@filemtime($file) < $olderThan) {
                @unlink($file);
            }
        }
    }

    /**
     * @template T
     * @param \Closure(): T $operation
     * @return T
     */
    private function locked(string $id, \Closure $operation): mixed
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Could not create the session directory.');
        }

        $lock = fopen($this->directory . '/lock-' . substr(hash('sha256', $id), 0, 1), 'c');

        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock the session store.');
        }

        try {
            return $operation();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function file(string $id): string
    {
        return $this->directory . '/' . hash('sha256', $id) . '.session';
    }
}
