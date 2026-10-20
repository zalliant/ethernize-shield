<?php

declare(strict_types=1);

namespace Ethernize\Shield\Strata;

use Ethernize\Shield\Identity\GenericIdentity;
use Ethernize\Shield\Identity\Identity;
use Ethernize\Shield\Identity\UpdatesPasswordHash;
use Ethernize\Shield\Identity\UserProvider;
use Ethernize\Strata\Connection;
use InvalidArgumentException;

/**
 * Loads users from a table through Strata. Optional: Shield works without it.
 *
 * Table and column names come from configuration, never from a request, and must be plain
 * identifiers. Values always travel as bindings.
 */
final class StrataUserProvider implements UserProvider, UpdatesPasswordHash
{
    /**
     * @param string $attributes extra columns made available as GenericIdentity::attribute(), comma separated
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly string $table = 'users',
        private readonly string $idColumn = 'id',
        private readonly string $loginColumn = 'email',
        private readonly string $passwordColumn = 'password',
        private readonly string $attributes = '',
    ) {
        foreach ([$table, $idColumn, $loginColumn, $passwordColumn, ...$this->attributeColumns()] as $name) {
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $name) !== 1) {
                throw new InvalidArgumentException('Shield users: table and column names must be plain identifiers.');
            }
        }
    }

    public function byIdentifier(string $identifier): ?Identity
    {
        return $this->find($this->idColumn, $identifier);
    }

    public function byLogin(string $login): ?Identity
    {
        return $this->find($this->loginColumn, $login);
    }

    public function updatePasswordHash(Identity $identity, string $hash): void
    {
        $this->connection->table($this->table)->where($this->idColumn, '=', $identity->identifier())->update([$this->passwordColumn => $hash]);
    }

    private function find(string $column, string $value): ?Identity
    {
        $row = $this->connection->table($this->table)
            ->select($this->idColumn, $this->passwordColumn, ...$this->attributeColumns())
            ->where($column, '=', $value)
            ->first();

        if ($row === null) {
            return null;
        }

        $hash = $row[$this->passwordColumn] ?? null;
        $extra = [];

        foreach ($this->attributeColumns() as $name) {
            $extra[$name] = $row[$name] ?? null;
        }

        return new GenericIdentity((string) $row[$this->idColumn], is_string($hash) && $hash !== '' ? $hash : null, $extra);
    }

    /**
     * @return list<string>
     */
    private function attributeColumns(): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $this->attributes)), static fn (string $name): bool => $name !== ''));
    }
}
