<?php

declare(strict_types=1);

namespace Ethernize\Shield\Auth;

use Ethernize\Core\Session\SessionInterface;
use Ethernize\Shield\Csrf\CsrfTokens;
use Ethernize\Shield\Identity\HasCredentialVersion;
use Ethernize\Shield\Identity\HasPassword;
use Ethernize\Shield\Identity\Identity;
use Ethernize\Shield\Identity\UpdatesPasswordHash;
use Ethernize\Shield\Identity\UserProvider;
use Ethernize\Shield\Password\Hasher;
use Ethernize\Shield\Throttle\LoginThrottle;

/**
 * Who is signed in on this request, and the login and logout lifecycle.
 *
 * The session stores only the identifier of the identity (plus a fingerprint of its password
 * hash, so changing a password signs the old sessions out). The identity is loaded again from
 * the UserProvider, at most once per request, so a deleted or disabled account stops working at
 * once. Login always replaces the session identifier and the CSRF secret; logout destroys the
 * whole session.
 */
final class Authenticator
{
    private const USER = '_shield.user';
    private const FINGERPRINT = '_shield.pw';
    private const SIGNED_IN_AT = '_shield.at';

    private const MAX_LOGIN_LENGTH = 255;

    private ?int $retryAfter = null;
    private bool $resolved = false;
    private ?Identity $identity = null;

    public function __construct(
        private readonly SessionInterface $session,
        private readonly UserProvider $users,
        private readonly Hasher $hasher,
        private readonly ?LoginThrottle $throttle = null,
        private readonly ?string $origin = null,
    ) {
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function user(): ?Identity
    {
        if ($this->resolved) {
            return $this->identity;
        }

        $this->resolved = true;
        $identifier = $this->session->get(self::USER);

        if (!is_string($identifier) || $identifier === '') {
            return null;
        }

        $identity = $this->users->byIdentifier($identifier);

        if ($identity === null || !hash_equals((string) $this->session->get(self::FINGERPRINT, ''), self::fingerprint($identity))) {
            // The account is gone, or its password changed: this session is no longer valid.
            $this->session->invalidate();

            return null;
        }

        return $this->identity = $identity;
    }

    /**
     * Checks a login and password and, when they are right, signs the identity in.
     * Wrong login and wrong password are indistinguishable, in the result and in the time taken.
     */
    public function attempt(string $login, #[\SensitiveParameter] string $password): ?Identity
    {
        $this->retryAfter = $this->throttle?->begin($login, $this->origin);

        if ($this->retryAfter !== null) {
            // Refused before anything is checked: not even the right password signs in while blocked.
            return null;
        }

        $identity = $login === '' || strlen($login) > self::MAX_LOGIN_LENGTH ? null : $this->users->byLogin($login);
        $hash = $identity instanceof HasPassword ? $identity->passwordHash() : null;
        $valid = $this->hasher->verify($password, $hash ?? $this->hasher->dummyHash());

        if (!$valid || $identity === null || $hash === null) {
            $this->throttle?->failed($login, $this->origin);

            return null;
        }

        $this->throttle?->succeeded($login, $this->origin);

        if ($this->hasher->needsRehash($hash) && $this->users instanceof UpdatesPasswordHash) {
            $this->users->updatePasswordHash($identity, $this->hasher->hash($password));
            // The session is bound to the stored hash: sign in the identity as it is stored now, or the very
            // next request would find a different hash and end this session.
            $identity = $this->users->byIdentifier($identity->identifier()) ?? $identity;
        }

        $this->login($identity);

        return $identity;
    }

    /**
     * Seconds to wait when the last attempt() was refused by the throttle, otherwise null. A controller
     * may answer 429 with it; the answer is the same for logins that exist and logins that do not.
     */
    public function retryAfter(): ?int
    {
        return $this->retryAfter;
    }

    /**
     * Signs an identity in without a password (after a check the application made itself).
     */
    public function login(Identity $identity): void
    {
        // A new identifier defeats session fixation; a new CSRF secret ends whatever the old session shared.
        $this->session->regenerate();
        // Created now, not on first use, so requests running in parallel after the login share one secret.
        CsrfTokens::rotate($this->session);
        $this->session->set(self::USER, $identity->identifier());
        $this->session->set(self::FINGERPRINT, self::fingerprint($identity));
        $this->session->set(self::SIGNED_IN_AT, time());

        $this->resolved = true;
        $this->identity = $identity;
    }

    /**
     * Ends the session completely: its data, its identifier and its cookie.
     */
    public function logout(): void
    {
        $this->session->invalidate();

        $this->resolved = true;
        $this->identity = null;
    }

    private static function fingerprint(Identity $identity): string
    {
        $hash = $identity instanceof HasPassword ? $identity->passwordHash() : null;
        $version = $identity instanceof HasCredentialVersion ? $identity->credentialVersion() : null;

        // Anything that changes either value ends the sessions made with the old one.
        return $hash === null && $version === null ? '' : hash('sha256', ($hash ?? '') . "\0" . ($version ?? ''));
    }
}
