<?php

declare(strict_types=1);

namespace Ethernize\Shield\Http;

/**
 * Holds Shield's state for the current request so services without access to the request
 * (the Weave tags, for example) can reach it. Registered with request scope: the Core
 * discards it after every request, so one user's state never reaches the next.
 */
final class RequestState
{
    public ?Shield $shield = null;
}
