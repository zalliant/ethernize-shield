<?php

declare(strict_types=1);

namespace Ethernize\Shield;

use Ethernize\Core\Application;
use Ethernize\Core\Manifest\ManifestContribution;
use Ethernize\Core\Manifest\ManifestContributor;

/**
 * Validates Shield's configuration while the Manifest is built and records its non-sensitive posture
 * under extensions.shield: which ability patterns have policies, whether CSRF is on and the session
 * lifetimes. Nothing about users, sessions or secrets is recorded; none of it exists at build time.
 */
final class ShieldManifestContributor implements ManifestContributor
{
    public function key(): string
    {
        return 'shield';
    }

    public function contribute(Application $application): ManifestContribution
    {
        $config = $application->config();
        $policies = ShieldProvider::policies($config->get('shield.policies', []));
        $abilities = array_keys($policies);
        sort($abilities);

        return new ManifestContribution([
            'csrf' => $config->get('shield.csrf.enabled', true) !== false,
            'throttle' => $config->get('shield.throttle.enabled', true) !== false,
            'policies' => $abilities,
            'idle_minutes' => (int) $config->get('shield.session.idle_minutes', 120),
            'absolute_minutes' => (int) $config->get('shield.session.absolute_minutes', 720),
        ]);
    }
}
