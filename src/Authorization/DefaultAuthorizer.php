<?php

declare(strict_types=1);

namespace Ethernize\Shield\Authorization;

use Ethernize\Core\Http\HttpException;
use Ethernize\Shield\Identity\HasPermissions;
use Ethernize\Shield\Identity\Identity;
use Psr\Container\ContainerInterface;

/**
 * The default Authorizer. Decision order:
 *
 *  1. no identity: denied;
 *  2. every policy registered for the ability is asked; one `false` denies;
 *  3. a `true` from a policy, or the ability listed by HasPermissions, allows;
 *  4. otherwise: denied.
 *
 * Policies are matched by exact ability ("posts.edit") or by prefix ("posts.*"), and are created
 * by the container only when needed.
 */
final class DefaultAuthorizer implements Authorizer
{
    /**
     * @param array<string, class-string<Policy>> $policies ability or prefix pattern => policy class
     */
    public function __construct(
        private readonly ContainerInterface $container,
        private readonly array $policies = [],
    ) {
    }

    public function allows(string $ability, ?Identity $identity, mixed $subject = null): bool
    {
        if ($identity === null || $ability === '') {
            return false;
        }

        $allowed = false;

        foreach ($this->policies as $pattern => $class) {
            if (!self::matches((string) $pattern, $ability)) {
                continue;
            }

            $policy = $this->container->get($class);
            $decision = $policy instanceof Policy ? $policy->check($identity, $ability, $subject) : false;

            if ($decision === false) {
                return false;
            }

            $allowed = $allowed || $decision === true;
        }

        return $allowed || ($identity instanceof HasPermissions && in_array($ability, $identity->permissions(), true));
    }

    /**
     * Like allows(), but answers a denial with a 403 for the Core error handler.
     *
     * @throws HttpException
     */
    public function authorize(string $ability, ?Identity $identity, mixed $subject = null): void
    {
        if (!$this->allows($ability, $identity, $subject)) {
            throw new HttpException(403, 'Forbidden');
        }
    }

    private static function matches(string $pattern, string $ability): bool
    {
        if (str_ends_with($pattern, '.*')) {
            $prefix = substr($pattern, 0, -1);

            return strlen($ability) > strlen($prefix) && str_starts_with($ability, $prefix);
        }

        return $pattern === $ability;
    }
}
