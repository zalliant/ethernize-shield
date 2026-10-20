<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Route guard: only signed-in users pass. Use it as route or group middleware:
 *
 *     Web::group('/account', $routes, [RequireAuthentication::class]);
 */
final class RequireAuthentication implements MiddlewareInterface
{
    public function __construct(private readonly FailureResponder $responder)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return Shield::from($request)->check()
            ? $handler->handle($request)
            : $this->responder->unauthenticated($request);
    }
}
