# OpenMage Carding Prevention

Rate-limits checkout and sign-in endpoints in OpenMage / Magento 1 to make card testing ("carding") and credential stuffing uneconomic.

Compatible with **PHP 7.4+**, Magento 1.9, OpenMage 19 and OpenMage 20. No PHP 8-only functions are used, so it does not depend on the Composer polyfills being loaded.

## Why this exists

A captcha on the checkout's billing step does not stop card testing. The billing step is passed once, and the payment and order endpoints are then submitted repeatedly inside that same session, so a one-off challenge never sees the repeats. Every order submission becomes an authorisation request at the payment gateway, which is what puts a merchant account at risk.

This module counts those submissions directly — per checkout session, per IP, and across the store as a whole — and refuses them.

## What it does

- Counts order placement per **checkout session** and per **IP** within a rolling window.
- Counts payment-method saves per **IP**, on a looser limit, since real shoppers do switch payment methods.
- Counts sign-in attempts per **IP** across the login form, the forgot-password form and Digitalpianism AjaxLogin. A successful login clears the counter, so only failures accumulate.
- Counts order placement **store-wide**, so a run spread across many addresses is still visible.
- Logs every refused attempt with the details needed to investigate.
- Clears a session's counter after a completed order.
- Hooks TM FireCheckout and Idev OneStepCheckout as well as stock one-page checkout, when those are installed.

Counters live in the application cache (Redis, APC or files, whatever the install uses), so nothing is written to the database and nothing needs cleaning up.

## Two ways to respond

**Block** refuses the address for a configurable period.

**Require Turnstile** keeps checkout open but demands a solved [Cloudflare Turnstile](https://github.com/fballiano/openmage-cloudflare-turnstile) challenge on every payment and order submission until the challenge window expires. This is the better setting where it is available: an address costs an attacker nothing to replace, a solved challenge does, and ordinary shoppers see nothing during normal trading.

The store-wide counter only ever escalates to a challenge, never a block — closing the shop would be worse than the problem it solves.

The Turnstile dependency is soft. `Fballiano_Turnstile` is not declared in `app/etc/modules`; the module checks at runtime whether it is installed and keyed, and falls back to blocking if it is not. Its site key, secret key and verification call are reused, so Turnstile stays configured in one place.

The widget is injected into the checkout payment form, whose contents are serialised when the order is submitted, so the token reaches both endpoints without patching core JavaScript. Tokens are single use, so the widget resets after each submission.

## Install

### Composer

```bash
composer require ysrtech/openmage-carding-prevention
```

### modman

```bash
modman clone https://github.com/ysrtech/OpenMage_CardingPrevention.git
```

### Manual

Copy `app/` over your installation, then flush the cache.

## Configure

**System → Configuration → YSR Tech → Carding Prevention**

The settings cover enabling the module, log-only mode, logging, real-client-IP handling, an IP allowlist, the per-session, per-IP and store-wide limits, the counting window, and the block or challenge duration. Every field carries a description in the admin panel.

Start with **Log Only** enabled. Attempts are recorded and nothing is refused, so you can see what your real traffic looks like before choosing limits. Set thresholds from your own order history — comfortably above a busy hour, well below an incident — rather than leaving the defaults.

### Behind a CDN or proxy, check this first

If the web server does not restore the real visitor IP, PHP sees the proxy's address and **every visitor shares one counter**, which would stop your whole store the moment a limit is reached. Verify what PHP sees during a live request:

```bash
php -r 'require "app/Mage.php"; Mage::app(); var_dump(Mage::helper("core/http")->getRemoteAddr());'
```

If that shows your CDN's addresses rather than real visitors, either configure `ngx_http_realip_module` / `mod_remoteip` with its published ranges, or enable **Trust CF-Connecting-IP** so the module reads that header itself.

Only trust a forwarded-IP header when the origin is reachable **exclusively** through the CDN. If the origin can be reached directly, the header can be forged.

## Verify it works

```bash
tail -f var/log/carding_prevention.log
```

Place a normal order and confirm nothing is logged. Then lower a limit temporarily on a staging store and confirm that the refusal happens, and in challenge mode that the widget appears and a solved challenge lets the order through.

## Notes for integrators

Refusals are returned as HTTP 200 with an error payload rather than a 4xx. Stock `opcheckout.js` treats a non-2xx response as a transport failure and redirects away from checkout, which would leave a legitimate shopper stranded with no message and no way to solve a challenge.

## This is one layer, not the whole defence

Also worth having:

1. **Rate limiting at your CDN or WAF** on the same endpoints, so floods never reach PHP. Short counting windows only catch fast attacks, so check what window your plan allows.
2. **3-D Secure** at the payment gateway, which removes the attacker's reason to test cards against you at all.
3. **Auto-decline on AVS or CVV mismatch**, plus whatever velocity controls your gateway offers.
4. **Turnstile** for the forms this module does not cover: registration, contact, reviews and newsletter.

## Licence

MIT
