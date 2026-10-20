<?php

declare(strict_types=1);

namespace Ethernize\Shield\Session;

use Ethernize\Core\Http\RequestAttributes;
use Ethernize\Core\Session\SessionInterface;
use Ethernize\Core\Session\SessionManagerInterface;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Cookie-based sessions with the protections that matter by default:
 *
 *  - the identifier is 256 random bits and only identifiers that exist in storage are accepted:
 *    one invented or planted by an attacker is ignored and a fresh one is issued (no fixation);
 *  - the cookie is HttpOnly and SameSite (Lax by default), Secure on HTTPS, and on HTTPS at the
 *    site root it also carries the "__Host-" prefix, so a subdomain or plain HTTP cannot overwrite it;
 *  - sessions expire when idle and after an absolute lifetime, both enforced on the server;
 *  - nothing is stored and no cookie is sent for a session that holds no data;
 *  - responses of requests that used the session are "private, no-store" unless the app chose otherwise.
 */
final class SessionManager implements SessionManagerInterface
{
    /** A session read this recently is not rewritten if nothing changed. */
    private const TOUCH_INTERVAL = 60;

    /** Writes retried when another request changed the same session at the same time. */
    private const ATTEMPTS = 5;

    private const ISSUED = 'issued';       // a new identifier was created: send the cookie
    private const SAVED = 'saved';         // same identifier, new data
    private const EXPIRED = 'expired';     // the session ended: remove the cookie
    private const UNCHANGED = 'unchanged';
    private const DROPPED = 'dropped';     // the session ended elsewhere: do not bring it back
    private const CONFLICT = 'conflict';

    public function __construct(
        private readonly SessionStore $store,
        private readonly int $idleSeconds = 7200,
        private readonly int $absoluteSeconds = 43200,
        private readonly string $cookie = 'ethernize_session',
        private readonly string $sameSite = 'Lax',
        private readonly string|bool $secure = 'auto',
        private readonly int $collectOneIn = 100,
    ) {
        if ($idleSeconds < 60 || $absoluteSeconds < $idleSeconds) {
            throw new InvalidArgumentException('Session lifetimes are invalid: idle must be at least 60 seconds and not longer than the absolute lifetime.');
        }

        if (!in_array($sameSite, ['Lax', 'Strict', 'None'], true) || ($sameSite === 'None' && $secure === false)) {
            throw new InvalidArgumentException('session same_site must be Lax or Strict (None requires Secure cookies).');
        }

        if (preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/', $cookie) !== 1 || !in_array($secure, ['auto', true, false], true)) {
            throw new InvalidArgumentException('Invalid session cookie settings.');
        }
    }

    public function start(ServerRequestInterface $request): SessionInterface
    {
        $secure = $this->secure === 'auto' ? $request->getUri()->getScheme() === 'https' : $this->secure === true;
        $base = $request->getAttribute(RequestAttributes::BASE_PATH, '');
        $path = is_string($base) && $base !== '' ? '/' . trim($base, '/') : '/';
        $name = ($secure && $path === '/' ? '__Host-' : '') . $this->cookie;

        $now = time();
        $presented = $request->getCookieParams()[$name] ?? null;
        $cookieSent = $presented !== null;

        if (Session::isValidId($presented)) {
            $record = $this->store->read($presented);

            if ($record !== null && $now - $record['active'] <= $this->idleSeconds && $now - $record['created'] <= $this->absoluteSeconds) {
                return new Session($presented, $record['data'], $record['created'], $record['active'], false, $secure, $path, $name, true);
            }

            if ($record !== null) {
                $this->store->delete($presented);
            }
        }

        return new Session(Session::newId(), [], $now, $now, true, $secure, $path, $name, $cookieSent);
    }

    public function commit(SessionInterface $session, ResponseInterface $response): ResponseInterface
    {
        if (!$session instanceof Session) {
            return $response;
        }

        $outcome = self::CONFLICT;

        for ($attempt = 0; $attempt < self::ATTEMPTS && $outcome === self::CONFLICT; $attempt++) {
            $outcome = $this->persist($session);
        }

        if ($outcome === self::CONFLICT) {
            // Never pretend the session was saved: the request fails instead (generic 500).
            throw new \RuntimeException('The session could not be saved because of concurrent changes.');
        }

        if ($outcome === self::ISSUED) {
            $response = $response->withAddedHeader('Set-Cookie', $this->cookieHeader($session, $session->id(), false));
        } elseif ($outcome === self::EXPIRED) {
            $response = $response->withAddedHeader('Set-Cookie', $this->cookieHeader($session, '', true));
        }

        if (in_array($outcome, [self::ISSUED, self::EXPIRED, self::SAVED], true) || $session->data() !== []) {
            $response = $this->private($response);
        }

        if (($outcome === self::ISSUED || $outcome === self::SAVED) && $this->collectOneIn > 0 && random_int(1, $this->collectOneIn) === 1) {
            $this->store->collect(time() - $this->absoluteSeconds);
        }

        return $response;
    }

    /**
     * One attempt to write the session. The latest stored record is read again and this request's
     * own changes are applied to it, so changes made meanwhile by other requests to other keys
     * survive. The write only happens if the record is still at the version that was read.
     *
     * A session that no longer exists in storage (logged out, regenerated or expired meanwhile) is
     * never recreated: its changes are dropped and no cookie is sent, so a stale request cannot
     * undo a logout or overwrite the cookie a newer request issued.
     */
    private function persist(Session $session): string
    {
        $now = time();
        $original = $session->originalId();

        if ($session->wasReset()) {
            if (!$session->isNew) {
                $this->store->delete($original);
            }

            $data = $session->applyTo([]);

            if ($data === []) {
                return $session->cookieSent ? self::EXPIRED : self::UNCHANGED;
            }

            return $this->store->write($session->id(), $data, $now, $now) ? self::ISSUED : self::CONFLICT;
        }

        if ($session->isNew) {
            $data = $session->applyTo([]);

            if ($data === []) {
                return self::UNCHANGED;
            }

            return $this->store->write($session->id(), $data, $now, $now) ? self::ISSUED : self::CONFLICT;
        }

        $latest = $this->store->read($original);

        if ($latest === null || $now - $latest['active'] > $this->idleSeconds || $now - $latest['created'] > $this->absoluteSeconds) {
            return self::DROPPED;
        }

        $merged = $session->applyTo($latest['data']);

        if ($merged === [] && ($session->hasChanges() || $session->wasRegenerated())) {
            return $this->store->delete($original, $latest['version']) ? self::EXPIRED : self::CONFLICT;
        }

        if ($session->wasRegenerated()) {
            if (!$this->store->write($session->id(), $merged, $latest['created'], $now)) {
                return self::CONFLICT;
            }

            if (!$this->store->delete($original, $latest['version'])) {
                // Someone changed or replaced the old record meanwhile: undo and look again.
                $this->store->delete($session->id());

                return self::CONFLICT;
            }

            return self::ISSUED;
        }

        if ($session->hasChanges()) {
            return $this->store->write($original, $merged, $latest['created'], $now, $latest['version']) ? self::SAVED : self::CONFLICT;
        }

        if ($now - $latest['active'] >= self::TOUCH_INTERVAL) {
            // Only the activity time changes; losing this race to another writer is harmless.
            $this->store->write($original, $latest['data'], $latest['created'], $now, $latest['version']);
        }

        return self::UNCHANGED;
    }

    private function private(ResponseInterface $response): ResponseInterface
    {
        return $response->hasHeader('Cache-Control') ? $response : $response->withHeader('Cache-Control', 'private, no-store');
    }

    private function cookieHeader(Session $session, string $value, bool $expire): string
    {
        $header = sprintf('%s=%s; Path=%s; HttpOnly; SameSite=%s', $session->cookieName, $value, $session->path, $this->sameSite);

        if ($expire) {
            $header .= '; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
        }

        return $session->secure || $this->sameSite === 'None' ? $header . '; Secure' : $header;
    }
}
