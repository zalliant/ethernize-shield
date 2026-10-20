<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Ethernize\Shield\Authorization\Authorizer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Route-level authorization. Route middleware is named by class (the Manifest cannot store objects),
 * so each protected ability is a small subclass:
 *
 *     final class CanManageNotes extends Authorize
 *     {
 *         protected function ability(): string
 *         {
 *             return 'notes.manage';
 *         }
 *     }
 *
 *     Web::on('/notes/new')->post([Notes::class, 'store'])->middleware(CanManageNotes::class);
 *
 * Guests get the "unauthenticated" answer, signed-in users who are not allowed get "forbidden".
 */
abstract class Authorize implements MiddlewareInterface
{
    public function __construct(
        private readonly Authorizer $authorizer,
        private readonly FailureResponder $responder,
    ) {
    }

    abstract protected function ability(): string;

    /** What the ability is about, when it depends on the request. */
    protected function subject(ServerRequestInterface $request): mixed
    {
        return null;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $user = Shield::from($request)->user();

        if ($user === null) {
            return $this->responder->unauthenticated($request);
        }

        return $this->authorizer->allows($this->ability(), $user, $this->subject($request))
            ? $handler->handle($request)
            : $this->responder->forbidden($request);
    }
}
