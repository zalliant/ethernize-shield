<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * Users held in memory: tests, prototypes and very small tools. Not for production data.
 */
final class ArrayUserProvider implements UserProvider
{
    /** @var array<string, Identity> */
    private array $byIdentifier = [];

    /** @var array<string, Identity> */
    private array $byLogin = [];

    /**
     * @param array<string, Identity> $users login => identity
     */
    public function __construct(array $users = [])
    {
        foreach ($users as $login => $identity) {
            $this->add((string) $login, $identity);
        }
    }

    public function add(string $login, Identity $identity): void
    {
        $this->byLogin[$login] = $identity;
        $this->byIdentifier[$identity->identifier()] = $identity;
    }

    public function byIdentifier(string $identifier): ?Identity
    {
        return $this->byIdentifier[$identifier] ?? null;
    }

    public function byLogin(string $login): ?Identity
    {
        return $this->byLogin[$login] ?? null;
    }
}
