<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What the client sees when Shield refuses a request. Bind your own implementation to change
 * the pages; keep the messages free of internal details.
 */
interface FailureResponder
{
    /** Nobody is signed in. */
    public function unauthenticated(ServerRequestInterface $request): ResponseInterface;

    /** Signed in, but not allowed. */
    public function forbidden(ServerRequestInterface $request): ResponseInterface;

    /** The CSRF token is missing or wrong, or the request came from another site. */
    public function csrfRejected(ServerRequestInterface $request): ResponseInterface;
}
