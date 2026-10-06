<?php
/**
 * Carding prevention for OpenMage / Magento 1.
 *
 * @category  YSRTech
 * @package   YSRTech_CardingPrevention
 * @license   MIT
 */
class YSRTech_CardingPrevention_Helper_Data extends Mage_Core_Helper_Abstract
{
    const XML_ENABLED          = 'cardingprevention/general/enabled';
    const XML_ACTION           = 'cardingprevention/general/action';
    const XML_LOG_ONLY         = 'cardingprevention/general/log_only';
    const XML_LOG_ENABLED      = 'cardingprevention/general/log_enabled';
    const XML_TRUST_CF         = 'cardingprevention/general/trust_cf_header';
    const XML_WHITELIST        = 'cardingprevention/general/whitelist_ips';
    const XML_ORDER_SESSION    = 'cardingprevention/limits/order_attempts_session';
    const XML_ORDER_IP         = 'cardingprevention/limits/order_attempts_ip';
    const XML_PAYMENT_IP       = 'cardingprevention/limits/payment_attempts_ip';
    const XML_LOGIN_IP         = 'cardingprevention/limits/login_attempts_ip';
    const XML_WINDOW_MINUTES   = 'cardingprevention/limits/window_minutes';
    const XML_BLOCK_MINUTES    = 'cardingprevention/limits/block_minutes';

    const XML_GLOBAL_ENABLED   = 'cardingprevention/breaker/enabled';
    const XML_GLOBAL_THRESHOLD = 'cardingprevention/breaker/orders_per_window';
    const XML_CHALLENGE_MIN    = 'cardingprevention/breaker/challenge_minutes';
    const XML_TURNSTILE_SELECT = 'cardingprevention/breaker/payment_form_selector';

    const ACTION_BLOCK     = 'block';
    const ACTION_TURNSTILE = 'turnstile';

    const LOG_FILE = 'carding_prevention.log';

    /** @var bool|null */
    protected $turnstileAvailable = null;

    public function isEnabled(): bool
    {
        return $this->isModuleEnabled() && Mage::getStoreConfigFlag(self::XML_ENABLED);
    }

    public function isLogOnly(): bool
    {
        return Mage::getStoreConfigFlag(self::XML_LOG_ONLY);
    }

    public function getOrderAttemptsPerSession(): int
    {
        return max(1, (int) Mage::getStoreConfig(self::XML_ORDER_SESSION));
    }

    public function getOrderAttemptsPerIp(): int
    {
        return max(1, (int) Mage::getStoreConfig(self::XML_ORDER_IP));
    }

    public function getPaymentAttemptsPerIp(): int
    {
        return max(1, (int) Mage::getStoreConfig(self::XML_PAYMENT_IP));
    }

    public function getLoginAttemptsPerIp(): int
    {
        return max(1, (int) Mage::getStoreConfig(self::XML_LOGIN_IP));
    }

    public function getWindowSeconds(): int
    {
        return max(60, (int) Mage::getStoreConfig(self::XML_WINDOW_MINUTES) * 60);
    }

    public function getBlockSeconds(): int
    {
        return max(60, (int) Mage::getStoreConfig(self::XML_BLOCK_MINUTES) * 60);
    }

    public function getBreakerThreshold(): int
    {
        return max(1, (int) Mage::getStoreConfig(self::XML_GLOBAL_THRESHOLD));
    }

    public function isBreakerEnabled(): bool
    {
        return Mage::getStoreConfigFlag(self::XML_GLOBAL_ENABLED);
    }

    public function getChallengeSeconds(): int
    {
        return max(60, (int) Mage::getStoreConfig(self::XML_CHALLENGE_MIN) * 60);
    }

    public function getPaymentFormSelector(): string
    {
        $selector = trim((string) Mage::getStoreConfig(self::XML_TURNSTILE_SELECT));

        return $selector !== '' ? $selector : '#co-payment-form';
    }

    /**
     * Challenging instead of blocking only makes sense when fballiano's
     * Turnstile module is installed and carries usable keys; otherwise the
     * configured action silently degrades to a hard block.
     */
    public function isTurnstileAvailable(): bool
    {
        if ($this->turnstileAvailable !== null) {
            return $this->turnstileAvailable;
        }

        $this->turnstileAvailable = false;

        if (!Mage::helper('core')->isModuleEnabled('Fballiano_Turnstile')) {
            return $this->turnstileAvailable;
        }

        $turnstile = Mage::helper('fballiano_turnstile');
        if (!$turnstile instanceof Fballiano_Turnstile_Helper_Data) {
            return $this->turnstileAvailable;
        }

        $this->turnstileAvailable = $turnstile->getSiteKey() !== '' && $turnstile->getSecretKey() !== '';

        return $this->turnstileAvailable;
    }

    /**
     * Challenge when configured to and Turnstile can actually run, block otherwise.
     */
    public function shouldChallenge(): bool
    {
        return Mage::getStoreConfig(self::XML_ACTION) === self::ACTION_TURNSTILE
            && $this->isTurnstileAvailable();
    }

    public function getTurnstileSiteKey(): string
    {
        return $this->isTurnstileAvailable()
            ? Mage::helper('fballiano_turnstile')->getSiteKey()
            : '';
    }

    /**
     * Server-side token check, delegated to the Turnstile module so the secret
     * key and verification endpoint stay configured in one place.
     */
    public function verifyTurnstileToken(string $token): bool
    {
        if ($token === '' || !$this->isTurnstileAvailable()) {
            return false;
        }

        return Mage::helper('fballiano_turnstile')->verify($token, $this->getClientIp());
    }

    /**
     * Real client IP. Behind Cloudflare the remote address is a Cloudflare edge
     * server unless the web server restores it, which would make every visitor
     * share one counter.
     */
    public function getClientIp(): string
    {
        if (Mage::getStoreConfigFlag(self::XML_TRUST_CF)) {
            $cfIp = Mage::app()->getRequest()->getServer('HTTP_CF_CONNECTING_IP');
            if ($cfIp && filter_var($cfIp, FILTER_VALIDATE_IP)) {
                return $cfIp;
            }
        }

        $remote = Mage::helper('core/http')->getRemoteAddr();

        return $remote ? (string) $remote : '0.0.0.0';
    }

    public function isWhitelisted(string $ip): bool
    {
        $raw = (string) Mage::getStoreConfig(self::XML_WHITELIST);
        if ($raw === '') {
            return false;
        }

        foreach (preg_split('/[\s,;]+/', $raw) as $entry) {
            $entry = trim($entry);
            if ($entry !== '' && $entry === $ip) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string,mixed> $context
     */
    public function log(string $message, array $context = []): void
    {
        if (!Mage::getStoreConfigFlag(self::XML_LOG_ENABLED)) {
            return;
        }

        $parts = [];
        foreach ($context as $key => $value) {
            $parts[] = $key . '=' . (is_scalar($value) ? (string) $value : json_encode($value));
        }

        Mage::log($message . ($parts ? ' ' . implode(' ', $parts) : ''), Zend_Log::WARN, self::LOG_FILE, true);
    }
}
