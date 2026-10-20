<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * An identity that can sign in with a password. Return the stored hash made by
 * Password\Hasher, or null when the account has no password (it then cannot sign in).
 */
interface HasPassword
{
    public function passwordHash(): ?string;
}
