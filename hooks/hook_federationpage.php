<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

/**
 * Add a link on the SimpleSAMLphp admin Federation page that points to the
 * oidanchor subordinate management UI.
 *
 * SSP's Federation controller calls Module::callHooks('federationpage', $t) after
 * building its own links array, so we append our link here.
 */
function oidanchor_hook_federationpage(Template $template): void
{
    if (!is_array($template->data['links'] ?? null)) {
        $template->data['links'] = [];
    }

    $template->data['links'][] = [
        'href' => Module::getModuleURL('oidanchor/admin/subordinates'),
        'text' => Translate::noop('OIDC Federation Subordinates'),
    ];

    $template->data['links'][] = [
        'href' => Module::getModuleURL('oidanchor/admin/policies'),
        'text' => Translate::noop('OIDC Federation Metadata Policies'),
    ];
}
