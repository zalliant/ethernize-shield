<?php

declare(strict_types=1);

namespace Ethernize\Shield\Session;

use Ethernize\Core\Session\SessionInterface;
use InvalidArgumentException;

/**
 * The session of one request. It holds a snapshot of the data read at the start and records what
 * this request changed, key by key; SessionManager applies those changes to the latest stored
 * record when the request ends, so a concurrent request's changes to other keys are not lost.
 *
 * Values must be JSON-safe (null, scalars and arrays of those): objects are refused, so what
 * is stored can always be read back without instantiating anything.
 */
final class Session implements SessionInterface
{
    private const MAX_DEPTH = 16;

    private readonly string $originalId;
    private bool $reset = false;

    /** @var array<string, array{0: 'set', 1: mixed}|array{0: 'remove'}> */
    private array $changes = [];

    /**
     * @param array<string, mixed> $data
     * @param bool $cookieSent whether the browser sent a session cookie that this request replaces or ends
     */
    public function __construct(
        private string $id,
        private array $data,
        public readonly int $createdAt,
        public readonly int $lastActive,
        public readonly bool $isNew,
        public readonly bool $secure,
        public readonly string $path,
        public readonly string $cookieName,
        public readonly bool $cookieSent,
    ) {
        $this->originalId = $id;
    }

    public static function newId(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function isValidId(mixed $id): bool
    {
        return is_string($id) && preg_match('/^[a-f0-9]{64}$/', $id) === 1;
    }

    public function id(): string
    {
        return $this->id;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function set(string $key, mixed $value): void
    {
        self::assertStorable($value, 0);

        $this->data[$key] = $value;
        $this->changes[$key] = ['set', $value];
    }

    public function remove(string $key): void
    {
        if (array_key_exists($key, $this->data)) {
            unset($this->data[$key]);
            $this->changes[$key] = ['remove'];
        }
    }

    /**
     * New identifier, same data. The old identifier stops working as soon as the request ends.
     */
    public function regenerate(): void
    {
        $this->id = self::newId();
    }

    /**
     * Drops the data and the identifier. What is set afterwards belongs to a new, unrelated session.
     */
    public function invalidate(): void
    {
        $this->id = self::newId();
        $this->data = [];
        $this->changes = [];
        $this->reset = true;
    }

    /**
     * The data as this request sees it.
     *
     * @return array<string, mixed>
     */
    public function data(): array
    {
        return $this->data;
    }

    /** The identifier the browser presented (or the one first created for a new session). */
    public function originalId(): string
    {
        return $this->originalId;
    }

    public function wasRegenerated(): bool
    {
        return $this->id !== $this->originalId;
    }

    /** True after invalidate(): nothing of the stored session may be kept. */
    public function wasReset(): bool
    {
        return $this->reset;
    }

    public function hasChanges(): bool
    {
        return $this->changes !== [];
    }

    /**
     * Applies this request's changes to $base, the latest stored data.
     *
     * @param array<string, mixed> $base
     * @return array<string, mixed>
     */
    public function applyTo(array $base): array
    {
        foreach ($this->changes as $key => $change) {
            if ($change[0] === 'set') {
                $base[$key] = $change[1];
            } else {
                unset($base[$key]);
            }
        }

        return $base;
    }

    private static function assertStorable(mixed $value, int $depth): void
    {
        if ($depth > self::MAX_DEPTH) {
            throw new InvalidArgumentException('Session values are nested too deeply.');
        }

        if ($value === null || is_scalar($value)) {
            return;
        }

        if (is_array($value)) {
            foreach ($value as $item) {
                self::assertStorable($item, $depth + 1);
            }

            return;
        }

        throw new InvalidArgumentException('Session values must be null, scalars or arrays of those; objects are not stored.');
    }
}
