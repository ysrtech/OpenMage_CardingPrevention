<?php
/**
 * @category  YSRTech
 * @package   YSRTech_CardingPrevention
 * @license   MIT
 */
class YSRTech_CardingPrevention_Model_System_Config_Source_Action
{
    /**
     * @return array<int,array<string,string>>
     */
    public function toOptionArray(): array
    {
        $helper    = Mage::helper('cardingprevention');
        $turnstile = $helper->isTurnstileAvailable()
            ? $helper->__('Require Turnstile (adaptive)')
            : $helper->__('Require Turnstile (adaptive) - needs Fballiano_Turnstile installed and keyed');

        return [
            [
                'value' => YSRTech_CardingPrevention_Helper_Data::ACTION_BLOCK,
                'label' => $helper->__('Block the address'),
            ],
            [
                'value' => YSRTech_CardingPrevention_Helper_Data::ACTION_TURNSTILE,
                'label' => $turnstile,
            ],
        ];
    }
}
