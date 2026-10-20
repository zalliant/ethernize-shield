<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

use Ethernize\Core\Http\RequestAttributes;
use Ethernize\Core\Http\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Web requests are redirected to the login page (with the page they wanted in `next`, only for GET);
 * API requests receive JSON. A request is an API request when it asks for JSON (Accept, or an
 * XMLHttpRequest, or a JSON body) without asking for HTML, or when its path is under `$apiPrefix`.
 */
final class DefaultFailureResponder implements FailureResponder
{
    public function __construct(
        private readonly string $loginUrl = '/login',
        private readonly string $apiPrefix = '/api',
    ) {
    }

    public function unauthenticated(ServerRequestInterface $request): ResponseInterface
    {
        if (self::wantsJson($request, $this->apiPrefix)) {
            return $this->json(401, 'unauthenticated', 'Authentication required.');
        }

        $base = $request->getAttribute(RequestAttributes::BASE_PATH, '');
        $target = $request->getUri()->getPath() . ($request->getUri()->getQuery() !== '' ? '?' . $request->getUri()->getQuery() : '');
        $login = (is_string($base) ? $base : '') . $this->loginUrl;

        if (in_array($request->getMethod(), ['GET', 'HEAD'], true) && Response::isLocalPath($target) && strlen($target) <= 2000) {
            $login .= '?next=' . rawurlencode($target);
        }

        return Response::redirect($login, 302)->withHeader('Cache-Control', 'no-store');
    }

    public function forbidden(ServerRequestInterface $request): ResponseInterface
    {
        return self::wantsJson($request, $this->apiPrefix)
            ? $this->json(403, 'forbidden', 'You do not have permission to do this.')
            : Response::text('Forbidden', 403, ['Cache-Control' => 'no-store']);
    }

    public function csrfRejected(ServerRequestInterface $request): ResponseInterface
    {
        return self::wantsJson($request, $this->apiPrefix)
            ? $this->json(403, 'csrf_mismatch', 'The request could not be verified. Reload the page and try again.')
            : Response::text('The request could not be verified. Reload the page and try again.', 403, ['Cache-Control' => 'no-store']);
    }

    public static function wantsJson(ServerRequestInterface $request, string $apiPrefix): bool
    {
        $base = $request->getAttribute(RequestAttributes::BASE_PATH, '');
        $path = $request->getUri()->getPath();

        if (is_string($base) && $base !== '' && str_starts_with($path, $base)) {
            $path = substr($path, strlen($base));
        }

        if ($apiPrefix !== '' && ($path === $apiPrefix || str_starts_with($path, rtrim($apiPrefix, '/') . '/'))) {
            return true;
        }

        $accept = strtolower($request->getHeaderLine('Accept'));
        $contentType = strtolower($request->getHeaderLine('Content-Type'));
        $json = str_contains($accept, 'application/json') || str_contains($accept, '+json')
            || strtolower($request->getHeaderLine('X-Requested-With')) === 'xmlhttprequest'
            || str_starts_with($contentType, 'application/json');

        return $json && !str_contains($accept, 'text/html');
    }

    private function json(int $status, string $code, string $message): ResponseInterface
    {
        return Response::json(['error' => ['code' => $code, 'message' => $message]], $status, ['Cache-Control' => 'no-store']);
    }
}
