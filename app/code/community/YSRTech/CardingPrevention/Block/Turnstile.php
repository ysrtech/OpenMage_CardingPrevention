<?php
/**
 * Renders the Turnstile widget into the checkout payment form, but only while
 * challenge mode is active. In normal trading nothing is output at all, so
 * regular shoppers never see a challenge.
 *
 * @category  YSRTech
 * @package   YSRTech_CardingPrevention
 * @license   MIT
 */
class YSRTech_CardingPrevention_Block_Turnstile extends Mage_Core_Block_Template
{
    public function canShow(): bool
    {
        /** @var YSRTech_CardingPrevention_Helper_Data $helper */
        $helper = Mage::helper('cardingprevention');

        if (!$helper->isEnabled() || !$helper->shouldChallenge() || $helper->isLogOnly()) {
            return false;
        }

        $ip = $helper->getClientIp();
        if ($helper->isWhitelisted($ip)) {
            return false;
        }

        /** @var YSRTech_CardingPrevention_Model_Throttle $throttle */
        $throttle = Mage::getSingleton('cardingprevention/throttle');

        return $throttle->isChallenged($ip)
            || $throttle->isChallenged(YSRTech_CardingPrevention_Model_Throttle::GLOBAL_SCOPE);
    }

    public function getSiteKey(): string
    {
        return Mage::helper('cardingprevention')->getTurnstileSiteKey();
    }

    public function getPaymentFormSelector(): string
    {
        return Mage::helper('cardingprevention')->getPaymentFormSelector();
    }

    /**
     * Cache would hand the same markup to everyone, challenged or not.
     */
    protected function _construct()
    {
        parent::_construct();
        $this->unsetData('cache_lifetime');
    }
}
