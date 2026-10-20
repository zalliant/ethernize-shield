<?php

declare(strict_types=1);

namespace Ethernize\Shield\Pulse;

use Ethernize\Pulse\Component;
use Ethernize\Pulse\Security\ActionAuthorizer;
use Ethernize\Shield\Authorization\Authorizer;
use Ethernize\Shield\Http\Shield;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authorizes Pulse actions declared with #[Action(authorize: 'ability')] through the Authorizer.
 * The signed-in user is the one of the request that carries the action, read again every time, so a
 * snapshot taken by one user never lets another act. Without a request, or a user, or Shield on the
 * request, the action is denied. The component is the subject of the ability.
 */
final class ShieldActionAuthorizer implements ActionAuthorizer
{
    public function __construct(private readonly Authorizer $authorizer)
    {
    }

    public function allows(string $ability, Component $component, array $arguments, ?ServerRequestInterface $request): bool
    {
        $shield = $request?->getAttribute(Shield::ATTRIBUTE);

        return $shield instanceof Shield && $this->authorizer->allows($ability, $shield->user(), $component);
    }
}
