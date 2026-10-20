<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Ethernize\Core\Http\RequestAttributes;
use Ethernize\Core\Session\SessionInterface;
use Ethernize\Shield\Auth\Authenticator;
use Ethernize\Shield\Csrf\CsrfTokens;
use Ethernize\Shield\Identity\UserProvider;
use Ethernize\Shield\Password\Hasher;
use Ethernize\Shield\Throttle\LoginThrottle;
use LogicException;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Makes authentication and CSRF available to the request, and enforces CSRF.
 *
 * It does not require a signed-in user: that is the job of the route guards. Every state-changing
 * request (anything but GET, HEAD, OPTIONS) must prove that it comes from a page of this site:
 *
 *  - a request that declares itself cross-site (Sec-Fetch-Site) or comes from another Origin is refused;
 *  - the token (form field `_token` or header `X-CSRF-Token`) must match the session.
 *
 * Paths in `$except` skip the token, but only for JSON requests, which a cross-site form cannot send.
 * Pulse's endpoint is exempt this way: it already requires a JSON body, the `X-Pulse` header, the same
 * Origin and a snapshot signed for the browser, so asking for another token would add nothing.
 */
final class ShieldMiddleware implements MiddlewareInterface
{
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    /**
     * @param list<string> $except         application paths exempt from the token (JSON requests only)
     * @param list<string> $trustedOrigins extra origins ("https://admin.example.com") allowed to post
     */
    public function __construct(
        private readonly ContainerInterface $container,
        private readonly Hasher $hasher,
        private readonly LoginThrottle $throttle,
        private readonly FailureResponder $responder,
        private readonly bool $csrf = true,
        private readonly array $except = [],
        private readonly array $trustedOrigins = [],
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $session = $request->getAttribute(RequestAttributes::SESSION);

        if (!$session instanceof SessionInterface) {
            // No session manager: refuse to run unprotected instead of silently skipping the checks.
            throw new LogicException('Shield needs a session manager.');
        }

        // Both are resolved for every request: they have request scope (or hold request-scoped services).
        /** @var UserProvider $users */
        $users = $this->container->get(UserProvider::class);
        /** @var RequestState $state */
        $state = $this->container->get(RequestState::class);

        $shield = new Shield(new Authenticator($session, $users, $this->hasher, $this->throttle, self::origin($request)), new CsrfTokens($session));
        $state->shield = $shield;
        $request = $request->withAttribute(Shield::ATTRIBUTE, $shield);

        if ($this->csrf && !in_array($request->getMethod(), self::SAFE_METHODS, true) && !$this->passes($request, $shield)) {
            return $this->responder->csrfRejected($request);
        }

        return $handler->handle($request);
    }

    /** The client address, as the Core resolved it (proxies are only trusted when configured). */
    private static function origin(ServerRequestInterface $request): ?string
    {
        $ip = $request->getAttribute(RequestAttributes::CLIENT_IP) ?? ($request->getServerParams()['REMOTE_ADDR'] ?? null);

        return is_string($ip) && $ip !== '' ? $ip : null;
    }

    private function passes(ServerRequestInterface $request, Shield $shield): bool
    {
        if (!$this->sameSite($request)) {
            return false;
        }

        if ($this->isExempt($request)) {
            return true;
        }

        $body = $request->getParsedBody();
        $token = is_array($body) ? ($body[CsrfTokens::FIELD] ?? null) : null;
        $token ??= $request->getHeaderLine(CsrfTokens::HEADER);

        return $shield->csrf()->verify($token);
    }

    private function isExempt(ServerRequestInterface $request): bool
    {
        if (!str_starts_with(strtolower($request->getHeaderLine('Content-Type')), 'application/json')) {
            return false;
        }

        $base = $request->getAttribute(RequestAttributes::BASE_PATH, '');
        $path = $request->getUri()->getPath();

        if (is_string($base) && $base !== '' && str_starts_with($path, $base)) {
            $path = substr($path, strlen($base));
        }

        return in_array($path, $this->except, true);
    }

    private function sameSite(ServerRequestInterface $request): bool
    {
        if (strtolower($request->getHeaderLine('Sec-Fetch-Site')) === 'cross-site') {
            return false;
        }

        if (!$request->hasHeader('Origin')) {
            return true;
        }

        $origin = strtolower(trim($request->getHeaderLine('Origin')));
        $uri = $request->getUri();
        $port = $uri->getPort();
        $own = strtolower($uri->getScheme() . '://' . $uri->getHost() . ($port !== null ? ':' . $port : ''));

        return $origin === $own || in_array($origin, array_map('strtolower', $this->trustedOrigins), true);
    }
}
