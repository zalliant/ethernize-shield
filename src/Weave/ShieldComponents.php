<?php

declare(strict_types=1);

namespace Ethernize\Shield\Weave;

use Ethernize\Shield\Csrf\CsrfTokens;
use Ethernize\Shield\Http\RequestState;
use Ethernize\Weave\Exception\RenderException;
use Ethernize\Weave\Runtime\NativeComponents;
use Ethernize\Weave\Runtime\NativeOutput;
use Ethernize\Weave\Runtime\Runtime;
use Psr\Container\ContainerInterface;

/**
 * Weave tags for CSRF protection:
 *
 *   <CsrfField />   a hidden input with a token, for forms: <input type="hidden" name="_token" value="...">
 *   <CsrfMeta />    <meta name="csrf-token" content="..."> for scripts that send the X-CSRF-Token header
 *
 * Rendering without an active request (Shield not in the pipeline) fails instead of printing nothing,
 * so a protected form can never be shipped without its token by accident.
 */
final class ShieldComponents implements NativeComponents
{
    public function __construct(private readonly ContainerInterface $container)
    {
    }

    public function names(): array
    {
        return ['CsrfField', 'CsrfMeta'];
    }

    public function render(string $name, array $props, string $identity, Runtime $runtime): string|NativeOutput
    {
        if ($props !== []) {
            throw new RenderException(sprintf('The component <%s> takes no properties.', $name));
        }

        /** @var RequestState $state */
        $state = $this->container->get(RequestState::class);
        $token = ($state->shield ?? throw new RenderException(sprintf('<%s> needs an active request with Shield.', $name)))->csrf()->token();
        $escaped = htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');

        return $name === 'CsrfField'
            ? sprintf('<input type="hidden" name="%s" value="%s">', CsrfTokens::FIELD, $escaped)
            : sprintf('<meta name="csrf-token" content="%s">', $escaped);
    }
}
