<?php

declare(strict_types=1);

namespace Ethernize\Shield\Identity;

/**
 * An identity that carries a flat list of abilities ("posts.edit"). The authorizer allows
 * an ability that is listed here, unless a policy denies it. There are no roles or
 * hierarchies: expand them in the application if it needs them.
 */
interface HasPermissions
{
    /**
     * @return list<string>
     */
    public function permissions(): array;
}
