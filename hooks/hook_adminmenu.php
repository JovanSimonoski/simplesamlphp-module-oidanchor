<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

/**
 * Add an "Federation TA" entry to the SimpleSAMLphp admin navigation menu.
 *
 * SSP's Menu::insert() calls Module::callHooks('adminmenu', $template), passing
 * the Template by reference so we can inject our entry directly into data['menu'].
 */
function oidanchor_hook_adminmenu(Template &$template): void
{
    $menuKey = 'menu';

    if (!isset($template->data[$menuKey]) || !is_array($template->data[$menuKey])) {
        return;
    }

    $entry = [
        'oidanchor' => [
            'url'  => Module::getModuleURL('oidanchor/admin/subordinates'),
            'name' => Translate::noop('Federation TA'),
        ],
    ];

    // Insert before 'logout' so the new entry appears in the middle of the nav.
    $logoutKey = 'logout';
    $logout    = null;

    if (
        array_key_exists($logoutKey, $template->data[$menuKey]) &&
        is_array($template->data[$menuKey][$logoutKey])
    ) {
        $logout = $template->data[$menuKey][$logoutKey];
        unset($template->data[$menuKey][$logoutKey]);
    }

    $template->data[$menuKey] += $entry;

    if ($logout !== null) {
        $template->data[$menuKey][$logoutKey] = $logout;
    }

    $template->getLocalization()->addModuleDomain('oidanchor');
}
