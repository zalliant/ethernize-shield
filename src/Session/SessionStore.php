<?php

declare(strict_types=1);

namespace Ethernize\Shield\Session;

/**
 * Persistence of session records. A record holds only JSON-safe data (never objects), so
 * reading storage can never instantiate classes.
 *
 * Every record has a version that grows with each write. Writes and deletions can be made
 * conditional on the version the caller read, which is all the manager needs to be safe under
 * concurrent requests: it re-reads, merges its own changes and writes only if nothing changed in
 * between (optimistic concurrency). A store therefore needs one atomic compare-and-set; in a
 * database that is `UPDATE ... WHERE id = ? AND version = ?`, in a cache the equivalent of a
 * transaction. No locks are held across requests.
 */
interface SessionStore
{
    /**
     * @return array{data: array<string, mixed>, created: int, active: int, version: int}|null null when absent or unreadable
     */
    public function read(string $id): ?array;

    /**
     * Stores a record.
     *
     * With $expectedVersion null the record is created, and the call fails if one already exists.
     * Otherwise it replaces the stored record only if its version is exactly $expectedVersion.
     * The stored version becomes $expectedVersion + 1 (1 for a new record).
     *
     * @param array<string, mixed> $data
     * @return bool false when the condition did not hold (nothing was written)
     */
    public function write(string $id, array $data, int $created, int $active, ?int $expectedVersion = null): bool;

    /**
     * Deletes a record, unconditionally or only if its version is $expectedVersion.
     *
     * @return bool true when a record was deleted
     */
    public function delete(string $id, ?int $expectedVersion = null): bool;

    /** Removes records not written since $olderThan (a Unix time). */
    public function collect(int $olderThan): void;
}
