<?php

declare(strict_types=1);

namespace Ethernize\Shield\Password;

interface Hasher
{
    public function hash(#[\SensitiveParameter] string $password): string;

    public function verify(#[\SensitiveParameter] string $password, string $hash): bool;

    public function needsRehash(string $hash): bool;

    /**
     * A valid hash of an unknown password. Verifying against it takes as long as a real
     * verification, so a missing account cannot be told apart by timing.
     */
    public function dummyHash(): string;
}
