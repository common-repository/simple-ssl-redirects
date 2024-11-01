=== Simple SSL Redirects ===
Contributors: edhicks
Tags: SSL, HTTPS, redirection, security, SEO
Requires at least: 4.6
Tested up to: 6.6
Requires PHP: 5.3
Stable tag: 1.1.2
License: GPLv2 or later

Lightweight plugin to ensure access via SSL/HTTPS. Uses 301 (permanent) redirects for SEO benefits. Optionally sets HSTS and forces canonical domain.

== Description ==

If your site has an SSL certificate you might find that you can access the site via both SSL (https) and non-SSL (http) URLs. This is a bad idea for security, and for SEO, as it can look like duplicate content on different URLs.

The answer to this is to redirect requests to non-SSL (http) URLs over to their SSL (https) equivalents using something called a 301 redirect. This tells the client (and search engines) that the resource they are looking for should always be accessed over SSL.  This plugin offers two methods to achieve this:

 - By intercepting WordPress pages at header time, and if they are not already being requested over HTTPS sending a 301 redirect header, or
 - By adding mod_rewrite rules in the .htaccess file to redirect all requests to their HTTPS equivalents using 301 redirects.

Optionally, this plugin can also set [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) headers for you, and make sure that all requests use the same hostname (i.e. fixing the issue where many sites can be accessed using both www. and non-www. URLs).

== Frequently Asked Questions ==

= Does this plugin install an SSL certificate? =

No. This plugin assumes you already have an SSL certificate installed, and that you are simply trying to ensure that all traffic uses HTTPS.

= Does this plugin fix mixed content issues? =

No, it does not fix any mixed content issues (resources such as scripts or images requested by your site using non-SSL URLs, which can cause warnings/broken padlock icons in address bars/loading of the resources being blocked) - although it might do so in the future.

= What is HSTS? =

The HTTP Strict Transport Security (HSTS) response header informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.

[Strict-Transport-Security reference on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

= What does "Force canonical domain" mean?

Depending on your configuration, your website might be accessible via both `yourdomain.com`  and  `www.yourdomain.com`. While using www. or not is personal preference, it's usually a good idea to make sure that **all** visitors access your site using whichever hostname you have chosen.

Selecting this option achieves this by applying a 301 redirection that makes sure that requests use the hostname you have specified in `WordPress Admin -> General Settings`.

= Troubleshooting =

This plugin checks your SSL certificate and warns you if it detects any issues, but if you enable it without a properly configured SSL certificate then you could end up not being able to access your website. If that happens please try the following:

 - First, try bypassing the SSL warning in your browser (sometimes the option to do this is hidden behind an "Advanced" or "Show Details" button, in Chrome you need to type "thisisunsafe" - search online for how to bypass SSL warnings in your particular browser).
 - If that doesn't work, try adding the following line in your wp-config.php file to disable the redirection plugin:
`define('DISABLE_SIMPLE_SSL_REDIRECTS', true);`
 - Or, edit your .htaccess file and remove everything between the lines
`# BEGIN Simple SSL Redirects`
and
`# END Simple SSL Redirects`

== Installation ==

= Automatically, from your plugin dashboard =

 1. Navigate to `Plugins > Add New` in your WP Admin dashboard.
 2. Search for `blucube simple ssl redirects`.
 3. Click the `Install` button, then `Activate`.

= Manual installation = 

 1. Search for `blucube simple ssl redirects` in the [WordPress Plugin Directory](https://wordpress.org/plugins/), and download it.
 2. Unzip and upload the `simple-ssl-redirects` directory to your `/wp-content/plugins/` directory.
 3. Activate the *Simple SSL Redirects* from the Plugins tab of your WP Admin dashboard. 

== Changelog ==

= 1.1.2 =

* Optimisation - only enqueue js and styles on plugin settings page.

= 1.1.1 =

* Fixed bug - setting a new option doesn't trigger an update hook. Potential for mismatched settings on first run.

= 1.1.0 =

* Added option to send HSTS policy header.
* Added option to redirect to canonical domain (enforcing www./non www. preference).
* Added kill switch functionality to disable plugin in case of missing/misconfigured SSL certificate.
* Tweaks to i18n to remove uses of WP core strings.
* Typo fixes.
