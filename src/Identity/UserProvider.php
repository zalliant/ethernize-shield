<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * Where identities come from. Implement it over any storage; Shield never assumes a database.
 * Both methods return null when nobody matches. They must not throw for unknown input.
 */
interface UserProvider
{
    /** Loads the identity whose Identity::identifier() is given (done on every authenticated request). */
    public function byIdentifier(string $identifier): ?Identity;

    /** Finds the identity that signs in with this login (an e-mail address or a user name). */
    public function byLogin(string $login): ?Identity;
}
