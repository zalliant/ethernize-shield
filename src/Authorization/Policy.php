<?php

declare(strict_types=1);

namespace Ethernize\Shield\Authorization;

use Ethernize\Shield\Identity\Identity;

/**
 * Rules for a group of abilities, registered in config/shield.php under 'policies'.
 *
 * Return true to allow, false to deny (a deny from any policy wins) or null to have no opinion.
 * Policies only run for a signed-in identity; guests are always denied.
 */
interface Policy
{
    public function check(Identity $identity, string $ability, mixed $subject = null): ?bool;
}
