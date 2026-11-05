<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

/**
 * The one status vocabulary for subordinates, shared by the admin UI and the admin REST API
 * (it matches the OpenAPI contract). Only `active` subordinates are served by the federation
 * fetch/list endpoints.
 */
enum SubordinateStatus: string
{
    case Active = 'active';

    case Blocked = 'blocked';

    case Pending = 'pending';

    case Inactive = 'inactive';


    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_column(self::cases(), 'value');
    }
}
