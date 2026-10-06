<?php
/**
 * Sliding-window counters and block list, kept in the application cache
 * (Redis, APC or files, whatever the installation is configured with).
 *
 * @category  YSRTech
 * @package   YSRTech_CardingPrevention
 * @license   MIT
 */
class YSRTech_CardingPrevention_Model_Throttle
{
    const CACHE_TAG         = 'YSR_CARDING';
    const PREFIX_COUNT      = 'ysr_carding_count_';
    const PREFIX_BLOCK      = 'ysr_carding_block_';
    const PREFIX_CHALLENGE  = 'ysr_carding_challenge_';
    const GLOBAL_SCOPE      = '__store__';

    /**
     * Increment the counter for a bucket and return the new value.
     * The window is a fixed TTL: the first hit creates the entry, and the whole
     * counter disappears once the TTL expires.
     */
    public function hit(string $bucket, string $ip, int $windowSeconds): int
    {
        $id      = $this->cacheId(self::PREFIX_COUNT . $bucket, $ip);
        $current = (int) Mage::app()->loadCache($id);
        $current++;

        Mage::app()->saveCache((string) $current, $id, [self::CACHE_TAG], $windowSeconds);

        return $current;
    }

    public function peek(string $bucket, string $ip): int
    {
        return (int) Mage::app()->loadCache($this->cacheId(self::PREFIX_COUNT . $bucket, $ip));
    }

    public function reset(string $bucket, string $ip): void
    {
        Mage::app()->removeCache($this->cacheId(self::PREFIX_COUNT . $bucket, $ip));
    }

    public function block(string $ip, int $seconds): void
    {
        Mage::app()->saveCache(
            (string) (time() + $seconds),
            $this->cacheId(self::PREFIX_BLOCK, $ip),
            [self::CACHE_TAG],
            $seconds
        );
    }

    public function isBlocked(string $ip): bool
    {
        $until = (int) Mage::app()->loadCache($this->cacheId(self::PREFIX_BLOCK, $ip));

        return $until > time();
    }

    public function unblock(string $ip): void
    {
        Mage::app()->removeCache($this->cacheId(self::PREFIX_BLOCK, $ip));
    }

    /**
     * Challenge mode: checkout keeps working, but every payment and order POST
     * has to carry a fresh Turnstile token until this expires.
     */
    public function challenge(string $scope, int $seconds): void
    {
        Mage::app()->saveCache(
            (string) (time() + $seconds),
            $this->cacheId(self::PREFIX_CHALLENGE, $scope),
            [self::CACHE_TAG],
            $seconds
        );
    }

    public function isChallenged(string $scope): bool
    {
        return ((int) Mage::app()->loadCache($this->cacheId(self::PREFIX_CHALLENGE, $scope))) > time();
    }

    public function challengeExpiry(string $scope): int
    {
        return (int) Mage::app()->loadCache($this->cacheId(self::PREFIX_CHALLENGE, $scope));
    }

    public function clearChallenge(string $scope): void
    {
        Mage::app()->removeCache($this->cacheId(self::PREFIX_CHALLENGE, $scope));
    }

    /**
     * Cache ids must be alphanumeric, so the IP is hashed rather than embedded.
     */
    protected function cacheId(string $prefix, string $ip): string
    {
        return $prefix . md5($ip);
    }
}
