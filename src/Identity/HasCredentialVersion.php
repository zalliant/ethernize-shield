<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * Optional: a value that changes whenever the account's credentials change (a password, a token,
 * a second factor). Every session remembers the value from its login and is ended when the current
 * one differs. Without it Shield uses a fingerprint of HasPassword::passwordHash(), which already
 * covers password changes. Either way the check runs against the identity loaded from your
 * UserProvider on every request, so it does not depend on where sessions are stored.
 *
 * Return a stable, non-secret string (an integer counter works well). Do not return the hash itself.
 */
interface HasCredentialVersion
{
    public function credentialVersion(): string;
}
