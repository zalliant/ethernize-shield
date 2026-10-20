<?php

declare(strict_types=1);

namespace Ethernize\Shield;

use Ethernize\Core\Application;
use Ethernize\Core\BootableProvider;
use Ethernize\Core\Container\Container;
use Ethernize\Core\Session\SessionManagerInterface;
use Ethernize\Pulse\Security\ActionAuthorizer;
use Ethernize\Shield\Authorization\Authorizer;
use Ethernize\Shield\Authorization\DefaultAuthorizer;
use Ethernize\Shield\Authorization\Policy;
use Ethernize\Shield\Http\DefaultFailureResponder;
use Ethernize\Shield\Http\FailureResponder;
use Ethernize\Shield\Http\RequestState;
use Ethernize\Shield\Http\ShieldMiddleware;
use Ethernize\Shield\Identity\NullUserProvider;
use Ethernize\Shield\Identity\UserProvider;
use Ethernize\Shield\Password\Hasher;
use Ethernize\Shield\Password\NativeHasher;
use Ethernize\Shield\Pulse\ShieldActionAuthorizer;
use Ethernize\Shield\Session\FileSessionStore;
use Ethernize\Shield\Session\SessionManager;
use Ethernize\Shield\Session\SessionStore;
use Ethernize\Shield\Strata\StrataUserProvider;
use Ethernize\Shield\Throttle\FileThrottleStore;
use Ethernize\Shield\Throttle\LoginThrottle;
use Ethernize\Shield\Throttle\ThrottleStore;
use Ethernize\Shield\Weave\ShieldComponents;
use Ethernize\Strata\Connection;
use Ethernize\Weave\Runtime\NativeComponentRegistry;
use InvalidArgumentException;

/**
 * Registers Shield: sessions, authentication, authorization and CSRF protection.
 * Shield is optional. An application that does not list this provider has none of it.
 *
 * Configuration (config/shield.php). Nothing in it may be a secret: the Manifest freezes
 * configuration into a file. Secrets (database passwords) stay in the environment.
 *
 *   users        'none' (default: nobody can sign in), 'strata', or the class of a UserProvider
 *                for 'strata': table, id, login, password, attributes (comma separated columns)
 *   policies     map of ability ("posts.edit") or prefix ("posts.*") to a Policy class
 *   login_url    where guests of web pages are sent (default "/login")
 *   api_prefix   paths under it always get JSON answers (default "/api")
 *   password     algorithm: "default", "bcrypt" or "argon2id"
 *   session      path (under var/, default var/sessions), cookie (default "ethernize_session"),
 *                idle_minutes (default 120), absolute_minutes (default 720),
 *                same_site ("Lax" default, "Strict"), secure ("auto" default: Secure on HTTPS)
 *   throttle     enabled (default true), max_attempts (5 per login and address), max_per_origin (20 failures
 *                per address), max_per_login (50 failures per login), decay_minutes (15), path (var/throttle)
 *   csrf         enabled (default true), except (JSON-only paths), trusted_origins
 *
 * Bind your own SessionManagerInterface, SessionStore, Hasher, Authorizer, FailureResponder or
 * UserProvider before this provider runs to replace the matching default.
 */
final class ShieldProvider implements BootableProvider
{
    private const DEV_ENVIRONMENTS = ['local', 'development', 'testing'];

    public function register(Container $container, Application $app): void
    {
        $config = $app->config();
        $policies = self::policies($config->get('shield.policies', []));

        foreach ($policies as $class) {
            $container->allow($class);
        }

        $session = (array) $config->get('shield.session', []);
        $this->guardProduction($app, $session);

        $container->scoped(RequestState::class, static fn (): RequestState => new RequestState());

        if (!$container->isBound(Hasher::class)) {
            $container->singleton(Hasher::class, static fn (): Hasher => new NativeHasher(self::algorithm($config->get('shield.password.algorithm', 'default'))));
        }

        if (!$container->isBound(UserProvider::class)) {
            // Request scope: a provider may hold request-scoped services (Strata's connection).
            $container->scoped(UserProvider::class, fn (Container $c): UserProvider => $this->users($c, (array) $config->get('shield.users', [])));
        }

        if (!$container->isBound(Authorizer::class)) {
            $container->singleton(Authorizer::class, static fn (Container $c): Authorizer => new DefaultAuthorizer($c, $policies));
        }

        if (!$container->isBound(FailureResponder::class)) {
            $login = (string) $config->get('shield.login_url', '/login');

            if (preg_match('~^/(?![/\\\\])[^\x00-\x1F\x7F\\\\]*$~', $login) !== 1) {
                throw new InvalidArgumentException('shield.login_url must be a path inside the application, such as "/login".');
            }

            $container->singleton(FailureResponder::class, static fn (): FailureResponder => new DefaultFailureResponder($login, (string) $config->get('shield.api_prefix', '/api')));
        }

        if (!$container->isBound(SessionStore::class)) {
            $container->singleton(SessionStore::class, fn (): SessionStore => new FileSessionStore($this->varDirectory($app, (string) ($session['path'] ?? 'var/sessions'), 'shield.session.path')));
        }

        if (!$container->isBound(SessionManagerInterface::class)) {
            $container->singleton(SessionManagerInterface::class, static fn (Container $c): SessionManagerInterface => new SessionManager(
                $c->get(SessionStore::class),
                (int) ($session['idle_minutes'] ?? 120) * 60,
                (int) ($session['absolute_minutes'] ?? 720) * 60,
                (string) ($session['cookie'] ?? 'ethernize_session'),
                (string) ($session['same_site'] ?? 'Lax'),
                $session['secure'] ?? 'auto',
            ));
        }

        $throttle = (array) $config->get('shield.throttle', []);

        if (!$container->isBound(ThrottleStore::class)) {
            $container->singleton(ThrottleStore::class, fn (): ThrottleStore => new FileThrottleStore($this->varDirectory($app, (string) ($throttle['path'] ?? 'var/throttle'), 'shield.throttle.path')));
        }

        $container->singleton(LoginThrottle::class, static fn (Container $c): LoginThrottle => new LoginThrottle(
            $c->get(ThrottleStore::class),
            (int) ($throttle['max_attempts'] ?? 5),
            (int) ($throttle['max_per_origin'] ?? 20),
            (int) ($throttle['max_per_login'] ?? 50),
            (int) ($throttle['decay_minutes'] ?? 15) * 60,
            ($throttle['enabled'] ?? true) !== false,
        ));

        $except = array_map('strval', (array) $config->get('shield.csrf.except', []));

        // Pulse's endpoint has its own request protection (see ShieldMiddleware).
        if (in_array('Ethernize\Pulse\PulseProvider', (array) $config->get('app.providers', []), true)) {
            $except[] = '/' . trim((string) $config->get('pulse.path', '/_pulse'), '/');
        }

        $container->singleton(ShieldMiddleware::class, static fn (Container $c): ShieldMiddleware => new ShieldMiddleware(
            $c,
            $c->get(Hasher::class),
            $c->get(LoginThrottle::class),
            $c->get(FailureResponder::class),
            $config->get('shield.csrf.enabled', true) !== false,
            $except,
            array_map('strval', (array) $config->get('shield.csrf.trusted_origins', [])),
        ));

        if (interface_exists(ActionAuthorizer::class) && !$container->isBound(ActionAuthorizer::class)) {
            $container->singleton(ActionAuthorizer::class, static fn (Container $c): ActionAuthorizer => new ShieldActionAuthorizer($c->get(Authorizer::class)));
        }
    }

    public function boot(Application $app): void
    {
        $container = $app->container();
        $app->addMiddleware(ShieldMiddleware::class);
        $app->addManifestContributor(new ShieldManifestContributor());

        if ($container->has(NativeComponentRegistry::class)) {
            $container->get(NativeComponentRegistry::class)->add(static fn (): ShieldComponents => new ShieldComponents($container));
        }
    }

    /**
     * @return array<string, class-string<Policy>>
     */
    public static function policies(mixed $configured): array
    {
        if (!is_array($configured)) {
            throw new InvalidArgumentException('shield.policies must be a map of ability to Policy class.');
        }

        foreach ($configured as $pattern => $class) {
            if (!is_string($pattern) || preg_match('/^[A-Za-z0-9_:-]+(\.[A-Za-z0-9_:-]+)*(\.\*)?$/', $pattern) !== 1 || !is_string($class) || !is_subclass_of($class, Policy::class)) {
                throw new InvalidArgumentException(sprintf('shield.policies: "%s" must map to a class that implements Ethernize\Shield\Authorization\Policy.', (string) $pattern));
            }
        }

        return $configured;
    }

    /**
     * @param array<string, mixed> $users
     */
    private function users(Container $container, array $users): UserProvider
    {
        $provider = $users['provider'] ?? 'none';

        if ($provider === 'none') {
            return new NullUserProvider();
        }

        if ($provider === 'strata') {
            if (!class_exists(Connection::class)) {
                throw new InvalidArgumentException('shield.users.provider is "strata" but the Strata module is not installed.');
            }

            return new StrataUserProvider(
                $container->get(Connection::class),
                (string) ($users['table'] ?? 'users'),
                (string) ($users['id'] ?? 'id'),
                (string) ($users['login'] ?? 'email'),
                (string) ($users['password'] ?? 'password'),
                (string) ($users['attributes'] ?? ''),
            );
        }

        if (!is_string($provider) || !is_subclass_of($provider, UserProvider::class)) {
            throw new InvalidArgumentException('shield.users.provider must be "none", "strata" or the class of a UserProvider.');
        }

        $container->allow($provider);

        /** @var UserProvider */
        return $container->get($provider);
    }

    private static function algorithm(mixed $name): string|int|null
    {
        return match ($name) {
            'default' => PASSWORD_DEFAULT,
            'bcrypt' => PASSWORD_BCRYPT,
            'argon2id' => defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : throw new InvalidArgumentException('This PHP build has no Argon2id.'),
            default => throw new InvalidArgumentException('shield.password.algorithm must be default, bcrypt or argon2id.'),
        };
    }

    /**
     * @param array<string, mixed> $session
     */
    private function guardProduction(Application $app, array $session): void
    {
        if (in_array($app->environment(), self::DEV_ENVIRONMENTS, true)) {
            return;
        }

        if (($session['secure'] ?? 'auto') === false) {
            throw new InvalidArgumentException('shield.session.secure cannot be false outside local, development and testing.');
        }
    }

    private function varDirectory(Application $app, string $relative, string $key): string
    {
        $normalized = str_replace('\\', '/', $relative);

        if (str_starts_with($normalized, '/') || preg_match('/^[A-Za-z]:/', $normalized) === 1 || in_array('..', explode('/', $normalized), true) || !str_starts_with($normalized, 'var/')) {
            throw new InvalidArgumentException($key . ' must be a path inside the application "var" directory, outside the public web root.');
        }

        return $app->basePath($normalized);
    }
}
