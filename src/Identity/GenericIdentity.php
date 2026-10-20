<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * A plain identity for applications that do not have a user class yet.
 * The password hash is kept out of debug output and serialization.
 */
final class GenericIdentity implements Identity, HasPassword, HasPermissions
{
    /**
     * @param array<string, mixed> $attributes
     * @param list<string>         $permissions
     */
    public function __construct(
        private readonly string $identifier,
        #[\SensitiveParameter] private readonly ?string $passwordHash = null,
        private readonly array $attributes = [],
        private readonly array $permissions = [],
    ) {
    }

    public function identifier(): string
    {
        return $this->identifier;
    }

    public function passwordHash(): ?string
    {
        return $this->passwordHash;
    }

    public function permissions(): array
    {
        return $this->permissions;
    }

    public function attribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    public function __debugInfo(): array
    {
        return ['identifier' => $this->identifier];
    }

    public function __serialize(): array
    {
        throw new \LogicException('An identity is never serialized; the session stores only its identifier.');
    }
}
