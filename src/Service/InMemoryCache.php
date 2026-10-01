<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/**
 * Minimal in-process PSR-16 cache used to dedupe entity-statement fetches within a single
 * resolve call (so the same entity configuration is not fetched twice). TTLs are ignored —
 * the instance is created per resolve call and discarded afterwards, so nothing persists.
 */
class InMemoryCache implements CacheInterface
{
    /** @var array<string,mixed> */
    private array $store = [];


    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->store) ? $this->store[$key] : $default;
    }


    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->store[$key] = $value;

        return true;
    }


    public function delete(string $key): bool
    {
        unset($this->store[$key]);

        return true;
    }


    public function clear(): bool
    {
        $this->store = [];

        return true;
    }


    /**
     * @param iterable<string> $keys
     * @return iterable<string,mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }


    /**
     * @param iterable<string,mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value);
        }

        return true;
    }


    /**
     * @param iterable<string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }


    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }
}
