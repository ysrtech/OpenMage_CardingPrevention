<?php
/**
 * Stops card-testing runs against the one-page checkout.
 *
 * Carders set up a quote once and then loop checkout/onepage/savePayment and
 * checkout/onepage/saveOrder with a fresh card number each time, so a captcha
 * on the billing step never sees them. These observers count the attempts
 * themselves and cut the session off.
 *
 * @category  YSRTech
 * @package   YSRTech_CardingPrevention
 * @license   MIT
 */
class YSRTech_CardingPrevention_Model_Observer
{
    const SESSION_KEY_ORDER_ATTEMPTS = 'ysr_carding_order_attempts';

    const BUCKET_ORDER   = 'order';
    const BUCKET_PAYMENT = 'payment';
    const BUCKET_LOGIN   = 'login';

    /**
     * checkout/onepage/saveOrder — one attempt equals one authorisation request
     * at the gateway, which is exactly what a card tester is buying.
     */
    public function throttleOrderPlacement(Varien_Event_Observer $observer): void
    {
        $helper = Mage::helper('cardingprevention');
        if (!$helper->isEnabled()) {
            return;
        }

        $controller = $observer->getControllerAction();
        if (!$controller->getRequest()->isPost()) {
            return;
        }

        $ip = $helper->getClientIp();
        if ($helper->isWhitelisted($ip)) {
            return;
        }

        /** @var YSRTech_CardingPrevention_Model_Throttle $throttle */
        $throttle = Mage::getSingleton('cardingprevention/throttle');

        if ($throttle->isBlocked($ip)) {
            $helper->log('Blocked IP attempted to place an order', ['ip' => $ip]);
            $this->deny($controller, $helper);
            return;
        }

        // Counted before anything else is decided: an attempt that gets refused
        // is still evidence of an attack in progress, and the breaker needs to
        // see the real arrival rate rather than only what the other rules let
        // through, or it never lights up during a distributed run.
        $this->countTowardsBreaker($helper, $throttle, $ip);

        if ($this->isChallenged($throttle, $ip) && !$this->passesTurnstile($helper, $controller)) {
            $helper->log('Order attempt without a valid Turnstile token', ['ip' => $ip]);
            $this->deny($controller, $helper, true);
            return;
        }

        $session        = Mage::getSingleton('checkout/session');
        $sessionCount   = (int) $session->getData(self::SESSION_KEY_ORDER_ATTEMPTS) + 1;
        $session->setData(self::SESSION_KEY_ORDER_ATTEMPTS, $sessionCount);

        $ipCount = $throttle->hit(self::BUCKET_ORDER, $ip, $helper->getWindowSeconds());

        $sessionLimit = $helper->getOrderAttemptsPerSession();
        $ipLimit      = $helper->getOrderAttemptsPerIp();

        if ($sessionCount <= $sessionLimit && $ipCount <= $ipLimit) {
            return;
        }

        $helper->log('Order attempt limit exceeded', [
            'ip'             => $ip,
            'session_count'  => $sessionCount,
            'session_limit'  => $sessionLimit,
            'ip_count'       => $ipCount,
            'ip_limit'       => $ipLimit,
            'quote_id'       => (int) $session->getQuoteId(),
            'email'          => $this->getQuoteEmail($session),
            'user_agent'     => (string) Mage::app()->getRequest()->getServer('HTTP_USER_AGENT'),
            'mode'           => $this->describeMode($helper),
        ]);

        $this->trip($helper, $throttle, $ip);
        $this->deny($controller, $helper, $helper->shouldChallenge());
    }

    /**
     * checkout/onepage/savePayment — cheaper for the attacker than saveOrder but
     * still part of the loop, so it gets a looser limit.
     */
    public function throttlePaymentSave(Varien_Event_Observer $observer): void
    {
        $helper = Mage::helper('cardingprevention');
        if (!$helper->isEnabled()) {
            return;
        }

        $controller = $observer->getControllerAction();
        if (!$controller->getRequest()->isPost()) {
            return;
        }

        $ip = $helper->getClientIp();
        if ($helper->isWhitelisted($ip)) {
            return;
        }

        /** @var YSRTech_CardingPrevention_Model_Throttle $throttle */
        $throttle = Mage::getSingleton('cardingprevention/throttle');

        if ($throttle->isBlocked($ip)) {
            $this->deny($controller, $helper);
            return;
        }

        if ($this->isChallenged($throttle, $ip) && !$this->passesTurnstile($helper, $controller)) {
            $this->deny($controller, $helper, true);
            return;
        }

        $count = $throttle->hit(self::BUCKET_PAYMENT, $ip, $helper->getWindowSeconds());
        $limit = $helper->getPaymentAttemptsPerIp();

        if ($count <= $limit) {
            return;
        }

        $helper->log('Payment save limit exceeded', [
            'ip'         => $ip,
            'count'      => $count,
            'limit'      => $limit,
            'user_agent' => (string) Mage::app()->getRequest()->getServer('HTTP_USER_AGENT'),
            'mode'       => $this->describeMode($helper),
        ]);

        $this->trip($helper, $throttle, $ip);
        $this->deny($controller, $helper, $helper->shouldChallenge());
    }

    /**
     * customer/account/loginPost, the forgot-password form and AjaxLogin.
     *
     * Credential stuffing looks the same as carding from the outside: one host
     * replaying a list against a form. Successful logins clear the counter, so
     * in practice only failures accumulate.
     */
    public function throttleLogin(Varien_Event_Observer $observer): void
    {
        $helper = Mage::helper('cardingprevention');
        if (!$helper->isEnabled()) {
            return;
        }

        $controller = $observer->getControllerAction();
        $request    = $controller->getRequest();
        if (!$request->isPost()) {
            return;
        }

        $ip = $helper->getClientIp();
        if ($helper->isWhitelisted($ip)) {
            return;
        }

        /** @var YSRTech_CardingPrevention_Model_Throttle $throttle */
        $throttle = Mage::getSingleton('cardingprevention/throttle');
        $isAjax   = $request->isXmlHttpRequest() || $request->getModuleName() === 'ajaxlogin';

        if ($throttle->isBlocked($ip)) {
            $this->denyLogin($controller, $helper, $isAjax);
            return;
        }

        $count = $throttle->hit(self::BUCKET_LOGIN, $ip, $helper->getWindowSeconds());
        $limit = $helper->getLoginAttemptsPerIp();

        if ($count <= $limit) {
            return;
        }

        $helper->log('Login attempt limit exceeded', [
            'ip'         => $ip,
            'count'      => $count,
            'limit'      => $limit,
            'login'      => (string) $request->getPost('login[username]', $request->getPost('email', '')),
            'route'      => $request->getModuleName() . '/' . $request->getControllerName() . '/' . $request->getActionName(),
            'user_agent' => (string) $request->getServer('HTTP_USER_AGENT'),
            'mode'       => $helper->isLogOnly() ? 'log_only' : 'blocked',
        ]);

        $throttle->block($ip, $helper->getBlockSeconds());
        $this->denyLogin($controller, $helper, $isAjax);
    }

    /**
     * A successful login means the visitor is not guessing, so the counter for
     * their address is cleared.
     */
    public function resetOnLogin(Varien_Event_Observer $observer): void
    {
        $helper = Mage::helper('cardingprevention');
        if (!$helper->isEnabled()) {
            return;
        }

        Mage::getSingleton('cardingprevention/throttle')
            ->reset(self::BUCKET_LOGIN, $helper->getClientIp());
    }

    /**
     * A completed order clears the per-session counter so a customer who comes
     * back to buy again starts fresh.
     */
    public function resetOnSuccess(Varien_Event_Observer $observer): void
    {
        Mage::getSingleton('checkout/session')->setData(self::SESSION_KEY_ORDER_ATTEMPTS, 0);
    }

    /**
     * Challenge mode is on for this visitor when their own address tripped a
     * limit, or when the store-wide breaker is lit.
     */
    protected function isChallenged(YSRTech_CardingPrevention_Model_Throttle $throttle, string $ip): bool
    {
        return $throttle->isChallenged($ip)
            || $throttle->isChallenged(YSRTech_CardingPrevention_Model_Throttle::GLOBAL_SCOPE);
    }

    protected function passesTurnstile(
        YSRTech_CardingPrevention_Helper_Data $helper,
        Mage_Core_Controller_Front_Action $controller
    ): bool {
        // Without a working Turnstile install there is no way to pass, so the
        // caller falls back to refusing the request outright.
        if (!$helper->isTurnstileAvailable()) {
            return false;
        }

        $token = (string) $controller->getRequest()->getPost('cf-turnstile-response', '');

        return $helper->verifyTurnstileToken($token);
    }

    /**
     * What happens when a limit is exceeded: either the address is blocked, or
     * it is put into challenge mode and has to solve Turnstile from now on.
     */
    protected function trip(
        YSRTech_CardingPrevention_Helper_Data $helper,
        YSRTech_CardingPrevention_Model_Throttle $throttle,
        string $ip
    ): void {
        if ($helper->isLogOnly()) {
            return;
        }

        if ($helper->shouldChallenge()) {
            $throttle->challenge($ip, $helper->getChallengeSeconds());
            return;
        }

        $throttle->block($ip, $helper->getBlockSeconds());
    }

    /**
     * Store-wide velocity. A shop that normally takes a couple of orders a day
     * has no business seeing dozens of attempts in an hour, however many
     * addresses they arrive from — this is the part IP and session counters
     * cannot see, because identities are free to the attacker.
     */
    protected function countTowardsBreaker(
        YSRTech_CardingPrevention_Helper_Data $helper,
        YSRTech_CardingPrevention_Model_Throttle $throttle,
        string $ip
    ): void {
        if (!$helper->isBreakerEnabled()) {
            return;
        }

        $scope = YSRTech_CardingPrevention_Model_Throttle::GLOBAL_SCOPE;
        $count = $throttle->hit(self::BUCKET_ORDER, $scope, $helper->getWindowSeconds());

        if ($count <= $helper->getBreakerThreshold() || $throttle->isChallenged($scope)) {
            return;
        }

        $helper->log('Store-wide order velocity breaker tripped', [
            'count'     => $count,
            'threshold' => $helper->getBreakerThreshold(),
            'window_s'  => $helper->getWindowSeconds(),
            'ip'        => $ip,
            'mode'      => $helper->isLogOnly()
                ? 'log_only'
                : ($helper->shouldChallenge() ? 'challenge_all' : 'no_action_without_turnstile'),
        ]);

        if ($helper->isLogOnly() || !$helper->shouldChallenge()) {
            // Blocking the whole store would be worse than the attack, so the
            // breaker only ever escalates to a challenge.
            return;
        }

        $throttle->challenge($scope, $helper->getChallengeSeconds());
    }

    protected function describeMode(YSRTech_CardingPrevention_Helper_Data $helper): string
    {
        if ($helper->isLogOnly()) {
            return 'log_only';
        }

        return $helper->shouldChallenge() ? 'challenge' : 'blocked';
    }

    /**
     * The one-page checkout talks JSON, so an HTML error page would leave the
     * shopper staring at a spinner. Both key styles are sent because themes and
     * checkout replacements disagree about which one they read.
     */
    protected function deny(
        Mage_Core_Controller_Front_Action $controller,
        YSRTech_CardingPrevention_Helper_Data $helper,
        bool $challenge = false
    ): void {
        if ($helper->isLogOnly()) {
            return;
        }

        $message = $challenge
            ? $helper->__('Please complete the security check below and submit your order again.')
            : $helper->__('For security reasons this checkout has been paused. Please contact us to complete your order.');

        // Deliberately HTTP 200. Stock opcheckout.js registers
        // onFailure: checkout.ajaxFailure, which does location.href =
        // failureUrl — so a 429 would bounce the shopper to the cart with no
        // message and no chance to solve the challenge. Magento's error
        // handling only runs on a 2xx carrying an error payload.
        $controller->setFlag('', Mage_Core_Controller_Varien_Action::FLAG_NO_DISPATCH, true);
        $controller->getResponse()
            ->setHeader('Content-Type', 'application/json', true)
            ->setBody(Mage::helper('core')->jsonEncode([
                'success'            => false,
                'error'              => 1,
                'error_messages'     => $message,
                'message'            => $message,
                'turnstile_required' => $challenge,
            ]));
    }

    /**
     * The standard login form is a plain POST, so it gets a session error and a
     * redirect back. AjaxLogin and anything sent with XMLHttpRequest get JSON.
     */
    protected function denyLogin(
        Mage_Core_Controller_Front_Action $controller,
        YSRTech_CardingPrevention_Helper_Data $helper,
        bool $isAjax
    ): void {
        if ($helper->isLogOnly()) {
            return;
        }

        $message = $helper->__('Too many sign-in attempts from your connection. Please try again later.');

        $controller->setFlag('', Mage_Core_Controller_Varien_Action::FLAG_NO_DISPATCH, true);
        $response = $controller->getResponse();

        if ($isAjax) {
            // 200 for the same reason as the checkout denial: a 4xx sends
            // Prototype down its failure path instead of showing the message.
            $response
                ->setHeader('Content-Type', 'application/json', true)
                ->setBody(Mage::helper('core')->jsonEncode([
                    'success' => false,
                    'error'   => 1,
                    'message' => $message,
                ]));
            return;
        }

        Mage::getSingleton('customer/session')->addError($message);
        $response->setRedirect(Mage::getUrl('customer/account/login'));
    }

    protected function getQuoteEmail(Mage_Checkout_Model_Session $session): string
    {
        $quote = $session->getQuote();
        if (!$quote || !$quote->getId()) {
            return '';
        }

        return (string) $quote->getCustomerEmail();
    }
}
