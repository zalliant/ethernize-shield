<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * Whoever is signed in. Shield only needs a stable identifier; everything else
 * about a user belongs to the application. The identifier is what the session
 * stores, so it must never change for the same person and must not be a secret.
 */
interface Identity
{
    public function identifier(): string;
}
