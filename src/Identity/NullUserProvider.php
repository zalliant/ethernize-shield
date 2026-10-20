<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/** Nobody exists. The default, so an application that configures no users can never authenticate anyone. */
final class NullUserProvider implements UserProvider
{
    public function byIdentifier(string $identifier): ?Identity
    {
        return null;
    }

    public function byLogin(string $login): ?Identity
    {
        return null;
    }
}
