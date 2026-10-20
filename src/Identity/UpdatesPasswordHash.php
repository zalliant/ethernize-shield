<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * Optional capability of a UserProvider: store a stronger hash when the algorithm
 * settings change. The Authenticator calls it right after a successful login.
 */
interface UpdatesPasswordHash
{
    public function updatePasswordHash(Identity $identity, string $hash): void;
}
