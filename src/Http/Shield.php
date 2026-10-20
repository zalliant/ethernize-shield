<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Ethernize\Shield\Auth\Authenticator;
use Ethernize\Shield\Csrf\CsrfTokens;
use Ethernize\Shield\Identity\Identity;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Shield's state for the current request: authentication and CSRF. ShieldMiddleware puts it in the
 * request attribute `Shield::ATTRIBUTE`; read it in controllers with Shield::from($request).
 */
final class Shield
{
    public const ATTRIBUTE = 'ethernize.shield';

    public function __construct(
        private readonly Authenticator $auth,
        private readonly CsrfTokens $csrf,
    ) {
    }

    /**
     * @throws LogicException when ShieldMiddleware did not run (a guard used without the provider fails closed)
     */
    public static function from(ServerRequestInterface $request): self
    {
        $shield = $request->getAttribute(self::ATTRIBUTE);

        if (!$shield instanceof self) {
            throw new LogicException('Shield is not active for this request: add Ethernize\Shield\ShieldProvider to app.providers.');
        }

        return $shield;
    }

    public function auth(): Authenticator
    {
        return $this->auth;
    }

    public function csrf(): CsrfTokens
    {
        return $this->csrf;
    }

    public function user(): ?Identity
    {
        return $this->auth->user();
    }

    public function check(): bool
    {
        return $this->auth->check();
    }
}
