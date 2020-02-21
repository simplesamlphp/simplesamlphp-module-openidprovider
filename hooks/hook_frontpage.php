<?php

/**
 * Hook to add the OpenID provider to the authentication tab.
 *
 * @param array &$links  The links on the frontpage, split into sections.
 * @return void
 */

function openidProvider_hook_frontpage(array &$links): void
{
    assert(array_key_exists("links", $links));

    $links['auth'][] = [
        'href' => \SimpleSAML\Module::getModuleURL('openidProvider/user.php'),
        'text' => '{openidProvider:openidProvider:title_no_user}',
    ];
}
