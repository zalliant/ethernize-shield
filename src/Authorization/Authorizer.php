<?php

declare(strict_types=1);

namespace Ethernize\Shield\Authorization;

use Ethernize\Shield\Identity\Identity;

/**
 * Answers "may this identity do this?". Anything that is not explicitly allowed is denied.
 */
interface Authorizer
{
    /**
     * @param mixed $subject what the ability is about (a record, a Pulse component, ...), when it matters
     */
    public function allows(string $ability, ?Identity $identity, mixed $subject = null): bool;
}
