<?php

/**
* Plugin Name: Simple SSL Redirects
* Description: Lightweight plugin to ensure access via SSL/HTTPS. Uses 301 (permanent) redirects for SEO benefits.
* Version: 1.1.2
* Requires at least: 4.6
* Requires PHP: 5.3
* License: GPLv2 or later
* Author: Blucube
* Author URI: https://blucube.net
* License: GPL2
* Text Domain: simple-ssl-redirects
*/

// disallow direct access
if(!defined('WPINC')) die;

class Simple_SSL_Redirects {
	
	public function __construct()
	{
		
		// register settings
		add_action('admin_init', function(){
			register_setting('ssslr_settings', 'ssslr_method', array('sanitize_callback' => array($this, 'sanitize_ssslr_method')));
			register_setting('ssslr_settings', 'ssslr_hsts', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
			register_setting('ssslr_settings', 'ssslr_canonical_domain', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
		});
		add_action('update_option_ssslr_method', array($this, 'options_changed'), 10, 2);
		add_action('update_option_ssslr_hsts', array($this, 'options_changed'), 10, 2);
		add_action('update_option_ssslr_canonical_domain', array($this, 'options_changed'), 10, 2);
		
		// add settings link on plugin admin screen
		add_filter('plugin_action_links_'.plugin_basename(__FILE__), function($links){
			array_unshift($links, '<a href="'.admin_url('options-general.php?page=ssslr').'">'. __('Settings', 'simple-ssl-redirects').'</a>');
			return $links;
		});
		
		// register options page in admin menu, enqueue scripts and css for page
		add_action('admin_menu', function(){
			$settings_page = add_options_page(__('Simple SSL Redirects Settings', 'simple-ssl-redirects'), 'Simple SSL Redirects', 'manage_options', 'ssslr', array($this, 'output_options_page'));
			add_action('load-'.$settings_page, function() {
				add_action('admin_enqueue_scripts', function() {
					wp_enqueue_script('ssslr_admin', plugin_dir_url( __FILE__ ).'ssslr-admin-js.js', [], filemtime(plugin_dir_path( __FILE__ ).'ssslr-admin-js.js'), true);
					wp_enqueue_style('ssslr_admin', plugin_dir_url( __FILE__ ).'ssslr-admin-styles.css', [], filemtime(plugin_dir_path( __FILE__ ).'ssslr-admin-styles.css'));
					wp_add_inline_style('ssslr_admin', $this->theme_colour_vars(), 'before');
				});
			});
		});
		
		// register kill switch behaviour
		add_action('admin_init', array($this, 'check_for_kill_switch'));
		
		// init option defaults to catch edge case on updating - adding doesn't fire update_option_foo
		add_action('admin_init', array($this, 'init_option_defaults'));
	
		// register function to handle redirection etc using non-htaccess method
		add_action('send_headers', array($this, 'ssl_redirect_and_headers'));
		
		// register activation hook
		register_activation_hook(__FILE__, array($this, 'activation'));
		
		// register deactivation hook
		register_deactivation_hook(__FILE__, array($this, 'deactivation'));
		
		// post activation redirect to settings page
		add_action('admin_init', array($this, 'activation_redirect'));
		
		// add alternate domain to allowed_redirect_hosts if necessary
		add_filter('allowed_redirect_hosts', array($this, 'allow_redirect_hosts'));
		
	}
	
	// create css variables based on user's admin colour theme
	function theme_colour_vars()
	{
		global $_wp_admin_css_colors; 
		if(!$_wp_admin_css_colors) return;
		$theme = get_user_meta(get_current_user_id(), 'admin_color', true);
		if(!key_exists($theme, $_wp_admin_css_colors)) return;
		$vars = [''];
		if(isset($_wp_admin_css_colors[$theme]->colors)) foreach($_wp_admin_css_colors[$theme]->colors as $key=>$col) $vars[] = "\t--wp-admin-color-$key: $col;";
		if(isset($_wp_admin_css_colors[$theme]->icon_colors)) foreach($_wp_admin_css_colors[$theme]->icon_colors as $key=>$col)	$vars[] = "\t--wp-admin-color-icon-$key: $col;";
		$vars[] = '';
		$styles = ":root {".join(PHP_EOL,$vars)."}";
		return $styles;
	}
	
	// init option defaults
	function init_option_defaults()
	{
		if(get_option('ssslr_hsts') === false) update_option('ssslr_hsts', 'off');
		if(get_option('ssslr_canonical_domain') === false) update_option('ssslr_canonical_domain', 'off');
	}
	
	// activation
	function activation()
	{
		
		// set option to show settings page on first activation
		if(get_option('ssslr_method') === false) update_option('ssslr_activation_redirect', true);
		
		// if not set, set method option to off
		// (using default in register_setting was causing issues with update_option_{} firing)
		if((get_option('ssslr_method') !== 'default') && (get_option('ssslr_method') !== 'htaccess')) update_option('ssslr_method', 'off');
		
		// if set to htaccess method, add directives
		if(get_option('ssslr_method') == 'htaccess') $this::add_htaccess_directives();
			
		// flush caches
		$this::flush_caches();
		
	}
	
	// deactivation
	function deactivation()
	{
		
		// remove htaccess directives
		$this::remove_htaccess_directives();
			
		// flush caches
		$this::flush_caches();
			
	}
	
	// uninstall
	static function uninstall()
	{
		
		// remove options
		delete_option('ssslr_method');
		delete_option('ssslr_hsts');
		delete_option('ssslr_canonical_domain');
			
	}
	
	// redirect to settings page on activation
	function activation_redirect()
	{
		if(get_option('ssslr_activation_redirect', false))
		{
			delete_option('ssslr_activation_redirect');
			wp_safe_redirect(admin_url('options-general.php?page=ssslr'));
			exit;
		}
	}
	
	// check for kill switch - deactivation method via constant set in wp-config
	function check_for_kill_switch()
	{
		if(defined('DISABLE_SIMPLE_SSL_REDIRECTS') && DISABLE_SIMPLE_SSL_REDIRECTS) {
			update_option('ssslr_method', 'off');
		}
	}
	
	// add alternate domain to allowed_redirect_hosts if necessary
	// e.g. www. / non-www. / local dev / server hostname / etc
	function allow_redirect_hosts($hosts)
	{
		$host = sanitize_text_field($_SERVER['HTTP_HOST']);
		if(!in_array($host, $hosts)) $hosts[] = $host;
		return $hosts;
	}
	
	// options page
	function output_options_page()
	{

		$ssl_verified = $this::has_ssl($_SERVER['HTTP_HOST']);
		$htaccess_writable = $this::htaccess_writable();
		$conflicting_plugins = $this::conflicting_plugins();
		$kill_switch = (defined('DISABLE_SIMPLE_SSL_REDIRECTS') && DISABLE_SIMPLE_SSL_REDIRECTS);
		$wp_urls_status = $this::test_wp_urls();
		$method = get_option('ssslr_method');
		$hsts = get_option('ssslr_hsts');
		$canonical_domain = get_option('ssslr_canonical_domain');
		
		if($kill_switch)
		{
			echo '<div class="notice notice-error is-dismissible">';
			echo '<p><strong>'.__('Plugin disabled', 'simple-ssl-redirects').':</strong> '.__('This plugin has been manually disabled. To use it again you need to edit your wp-config.php file and remove the following line: <pre>define(\'DISABLE_SIMPLE_SSL_REDIRECTS\', true);</pre>', 'simple-ssl-redirects').'</p>';
			echo '</div>';
		}
		
		if(!$ssl_verified)
		{
			echo '<div class="notice notice-error is-dismissible">';
			echo '<p><strong>'.__('SSL Certificate Error', 'simple-ssl-redirects').':</strong> '.__('Simple SSL Redirects was unable to verify your site\'s SSL certificate. You should install a certificate and/or ensure it is configured correctly <strong>before</strong> enabling redirection. Enabling redirection without a correctly configured SSL certificate could result in you being unable to access your website.', 'simple-ssl-redirects').'</p>';
			echo '</div>';
		}

		if(!$wp_urls_status['siteurl'] || !$wp_urls_status['home'])
		{
			$fields = '';
			if(!$wp_urls_status['siteurl']) $fields .= '<strong>'.__('WordPress Address (URL)', 'simple-ssl-redirects').'</strong>';
			if(!$wp_urls_status['siteurl'] && !$wp_urls_status['home']) $fields .= ' '.__('and', 'simple-ssl-redirects').' ';
			if(!$wp_urls_status['home']) $fields .= '<strong>'.__('Site Address (URL)', 'simple-ssl-redirects').'</strong>';
			echo '<div class="notice notice-warning is-dismissible">';
			$settings_link = '<a href="'.admin_url('options-general.php').'">'.__('General Settings', 'simple-ssl-redirects').'</a>';
			echo '<p><strong>'.__('Warning', 'simple-ssl-redirects').':</strong> ';
			printf(__('Your %1$s in %2$s should probably be set to an SSL (https://) URL.', 'simple-ssl-redirects'), $fields, $settings_link);
			echo '</p>';
			echo '</div>';
		}
		
		if(count($conflicting_plugins) > 0)
		{
			echo '<div class="notice notice-warning is-dismissible">';
			echo '<p><strong>'.__('Warning', 'simple-ssl-redirects').':</strong> '.__('Having multiple redirection plugins active at the same time could cause issues. You should ensure that all settings are compatible and consider disabling plugins that duplicate functionality.', 'simple-ssl-redirects').' <i>('.__('Detected', 'simple-ssl-redirects').': '.implode(', ', $conflicting_plugins).')</i></p>';
			echo '</div>';
		}

		echo '<div class="wrap ssslr-opts">';
		echo '<h1>Simple SSL Redirects</h1>';
		
		echo '<div class="flex">';
		
		echo '<form action="options.php" method="post">';
		settings_fields('ssslr_settings');
		echo '<h3>'.__('SSL 301 Redirection', 'simple-ssl-redirects').'</h3>';
		
		echo '<div class="ssslr-input">';
		echo '<input type="radio" id="ssslr-method-off" name="ssslr_method" value="off"';
		if($method == 'off') echo ' checked';
		echo '>';
		echo '<div>';
		echo '<label for="ssslr-method-off"><strong>'.__('Off', 'simple-ssl-redirects').'</strong></label>';
		echo '<p class="description">'.__('No redirection will take place.', 'simple-ssl-redirects').'</p>';
		echo '</div>';
		echo '</div>';
		
		echo '<div class="ssslr-input">';
		echo '<input type="radio" id="ssslr-method-default" name="ssslr_method" value="default"';
		if($method == 'default') echo ' checked';
		if($kill_switch || !$ssl_verified) echo ' disabled';
		echo '>';
		echo '<div>';
		echo '<label for="ssslr-method-default"><strong>'.__('Using WordPress', 'simple-ssl-redirects').'</strong></label>';
		echo '<p class="description">'.__('Will only redirect pages under WordPress control.', 'simple-ssl-redirects').'</p>';
		echo '</div>';
		echo '</div>';
		
		echo '<div class="ssslr-input">';
		echo '<input type="radio" id="ssslr-method-htaccess" name="ssslr_method" value="htaccess"';
		if($method == 'htaccess') echo ' checked';
		if($kill_switch || !$ssl_verified || !$htaccess_writable) echo ' disabled';
		echo '>';
		echo '<div>';
		echo '<label for="ssslr-method-htaccess"><strong>'.__('Using .htaccess', 'simple-ssl-redirects').'</strong></label>';
		if($htaccess_writable) echo '<p class="description">'.__('Will redirect all HTTP requests.', 'simple-ssl-redirects').'</p>';
		else echo '<p class="description">'.__('It looks like either your site doesn\'t use an .htaccess file or the file is not writable.', 'simple-ssl-redirects').'</p>';
		echo '</div>';
		echo '</div>';
		
		echo '<div class="additional-options"';
		if($method == 'off') echo ' style="display:none;"';
		echo '>';
		
		echo '<h3>'.__('Additional Options', 'simple-ssl-redirects').'</h3>';
		
		echo '<div class="ssslr-input">';
		echo '<input type="checkbox" id="ssslr-hsts" name="ssslr_hsts"';
		if($hsts == 'on') echo ' checked';
		echo '>';
		echo '<div>';
		echo '<label for="ssslr-hsts"><strong>'.__('Implement HSTS', 'simple-ssl-redirects').'</strong><a href="#" class="help open-accordion" data-accordion-id="sssl-help-hsts">?</a></label>';
		echo '<p class="description">'.__('Sets HTTP Strict Transport Security header.', 'simple-ssl-redirects').'</p>';
		echo '</div>';
		echo '</div>';
		
		echo '<div class="ssslr-input">';
		echo '<input type="checkbox" id="ssslr-canonical-domain" name="ssslr_canonical_domain"';
		if($canonical_domain == 'on') echo ' checked';
		echo '>';
		echo '<div>';
		echo '<label for="ssslr-canonical-domain"><strong>'.__('Force canonical domain', 'simple-ssl-redirects').'</strong><a href="#" class="help open-accordion" data-accordion-id="sssl-help-canonical-domain">?</a></label>';
		echo '<p class="description">'.__('Ensure all requests use', 'simple-ssl-redirects').' <strong>'.$this::siteurl_hostname().'</strong>.</p>';
		echo '</div>';
		echo '</div>';
		
		echo '</div>';
		
		submit_button();
		echo '</form>';
		
		echo '<div class="card accordion">';

		echo '<h3><a href="#" class="open">'.__('What does this plugin do?', 'simple-ssl-redirects').'</a></h3>';
		echo '<div>';
		echo '<p>'.__('If your site has an SSL certificate you might find that you can access the site via both SSL (https) and non-SSL (http) URLs. This is a bad idea for security, and for SEO, as it can look like duplicate content on different URLs.', 'simple-ssl-redirects').'</p>';
		echo '<p>'.__('The answer to this is to redirect requests to non-SSL (http) URLs over to their SSL (https) equivalents using something called a 301 redirect. This tells the client (and search engines) that the resource they are looking for should always be accessed over SSL. This plugin offers two methods to achieve this.', 'simple-ssl-redirects').'</p>';
		echo '</div>';
		
		
		echo '<h3><a href="#">'.__('What does this plugin NOT do?', 'simple-ssl-redirects').'</a></h3>';
		echo '<div>';
		echo '<ul class="ul-disc">';
		echo '<li>'.__('It does not install any SSL certificates. If your site isn\'t yet configured to work over SSL at all then you should address that first. <strong>If you enable redirection without an SSL certificate installed it could result in you being unable to access your website.</strong>', 'simple-ssl-redirects').'</li>';
		echo '<li>'.__('It does not fix any mixed content issues (resources such as scripts or images requested by your site using non-SSL URLs, which can cause warnings/broken padlock icons in address bars/loading of the resources being blocked) - although it might do so in the future.', 'simple-ssl-redirects').'</li>';
		echo '</ul>';
		echo '</div>';
		
		echo '<h3><a href="#" id="sssl-help-hsts">'.__('What is HSTS?', 'simple-ssl-redirects').'</a></h3>';
		echo '<div>';
		echo '<p>'.__('The HTTP Strict Transport Security (HSTS) response header informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.', 'simple-ssl-redirects').'</p>';
		echo '<p><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security" target="_blank">'.__('Strict-Transport-Security reference on MDN', 'simple-ssl-redirects').'</a></p>';
		echo '</div>';
		
		echo '<h3><a href="#" id="sssl-help-canonical-domain">'.__('What does "Force canonical domain" mean?', 'simple-ssl-redirects').'</a></h3>';
		echo '<div>';
		echo '<p>'.__('Depending on your configuration, your website might be accessible via both <strong>yourdomain.com</strong> and <strong>www.yourdomain.com</strong>. While using www. or not is personal preference, it\'s usually a good idea to make sure that all visitors access your site using whichever hostname you have chosen.', 'simple-ssl-redirects').'</p>';
		$settings_link = '<a href="'.admin_url('options-general.php').'">'.__('General Settings', 'simple-ssl-redirects').'</a>';
		echo '<p>';
		printf(__('Selecting this option achieves this by applying a 301 redirection that makes sure that requests use the hostname you have specified in %1$s.', 'simple-ssl-redirects'), $settings_link);
		echo '</div>';
		
		echo '<h3><a href="#">'.__('Troubleshooting', 'simple-ssl-redirects').'</a></h3>';
		echo '<div>';
		echo '<p>'.__('This plugin checks your SSL certificate and warns you if it detects any issues, but if you enable it without a properly configured SSL certificate then you could end up not being able to access your website. If that happens please try the following:').'</p>';
		echo '<ul class="ul-disc">';
		echo '<li>'.__('First, try bypassing the SSL warning in your browser (sometimes the option to do this is hidden behind an "Advanced" or "Show Details" button, in Chrome you need to type "thisisunsafe" - search online for how to bypass SSL warnings in your particular browser).', 'simple-ssl-redirects').'</li>';
		echo '<li>'.__('If that doesn\'t work, try adding the following line in your wp-config.php file to disable the redirection plugin:', 'simple-ssl-redirects').'<pre>define(\'DISABLE_SIMPLE_SSL_REDIRECTS\', true);</pre></li>';
		echo '<li>'.__('Or, edit your .htaccess file and remove everything between the lines', 'simple-ssl-redirects').'<pre># BEGIN Simple SSL Redirects</pre>'.__('and').'<pre># END Simple SSL Redirects</pre></li>';
		echo '</ul>';
		echo '</div>';
		
		echo '</div>';
		
		echo '</div>';
		
		echo '</div>';
	}
	
	// sanitize redirect method
	function sanitize_ssslr_method($input)
	{
		$allowed_values = array('off', 'default', 'htaccess');
		return (in_array($input, $allowed_values)) ? $input : $allowed_values[0];
	}
	
	// sanitize checkbox
	function sanitize_checkbox($input)
	{
		$allowed_values = array('off', 'on');
		return (in_array($input, $allowed_values)) ? $input : $allowed_values[0];
	}
	
	// options changed
	function options_changed()
	{
		if(get_option('ssslr_method') == 'htaccess') $this::add_htaccess_directives();
		else $this::remove_htaccess_directives();
		$this::flush_caches();			
	}
	
	// add .htaccess directives
	function add_htaccess_directives()
	{
		$this::remove_htaccess_directives();
		if($this::htaccess_writable())
		{
			$htaccess = file(get_home_path().'.htaccess', FILE_IGNORE_NEW_LINES);
			$directives = array(
				'',
				'# BEGIN Simple SSL Redirects',
				'<IfModule mod_rewrite.c>',
				'RewriteEngine On',
				'RewriteCond %{HTTP:X-Forwarded-Proto} !https',
				'RewriteCond %{HTTPS} off',
				'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]',
			);
			if((get_option('ssslr_canonical_domain') == 'on') && $this::siteurl_hostname())
			{
				$directives = array_merge($directives, array(
					'RewriteCond %{HTTP_HOST} !^'.str_replace('.', '\.', $this::siteurl_hostname()).' [NC]',
					'RewriteRule ^(.*) https://'.$this::siteurl_hostname().'/$1 [R=301,L,QSA]',
				));	
			}
			$directives = array_merge($directives, array(
				'</IfModule>',
			));
			if(get_option('ssslr_hsts') == 'on')
			{
				$directives = array_merge($directives, array(
					'<IfModule mod_headers.c>',
					'Header set Strict-Transport-Security "max-age=31536000" env=HTTPS',
					'</IfModule>',
				));	
			}
			$directives = array_merge($directives, array(
				'# END Simple SSL Redirects',
				'',
			));
			$insert_at_line = false;
			for($i = 0; $i < count($htaccess); $i++)
			{
				if(stristr($htaccess[$i], '# BEGIN WordPress'))
				{
					$insert_at_line = $i;
					break;
				}
			}
			if($insert_at_line === false) $htaccess = array_merge($htaccess, $directives);
			else array_splice($htaccess, $insert_at_line, 0, $directives);
			$htaccess = $this::tidy_htaccess($htaccess);
			file_put_contents(get_home_path().'.htaccess', implode(PHP_EOL, $htaccess));
		}
	}
	
	// remove .htaccess directives
	function remove_htaccess_directives()
	{
		if($this::htaccess_writable())
		{
			$htaccess = file(get_home_path().'.htaccess', FILE_IGNORE_NEW_LINES);
			$start_line = false;
			$end_line = false;
			for($i = 0; $i < count($htaccess); $i++)
			{
				if(stristr($htaccess[$i], '# BEGIN Simple SSL Redirects')) $start_line = $i;
				if(stristr($htaccess[$i], '# END Simple SSL Redirects')) $end_line = $i;
				if(($start_line !== false) && ($end_line !== false)) break;
			}
			if(($start_line !== false) && ($end_line !== false))
			{
				$num_lines = $end_line - $start_line + 1;
				if(($num_lines > 0) && ($num_lines < 16))
				{
					array_splice($htaccess, $start_line, $num_lines);
					$htaccess = $this::tidy_htaccess($htaccess);
					file_put_contents(get_home_path().'.htaccess', implode(PHP_EOL, $htaccess));	
				}
			}
		}
	}
	
	// tidy multiple empty lines from htaccess
	function tidy_htaccess($htaccess)
	{
		$new_htaccess = array();
		for($i = 0; $i < count($htaccess); $i++)
		{
			if((trim($htaccess[$i]) != '') || (($i > 0) && (trim($htaccess[$i-1]) != '')))
			{
				$new_htaccess[] = $htaccess[$i];
			}
		}
		return $new_htaccess;
	}
	
	// check for potentially conflicting plugins
	function conflicting_plugins()
	{
		$plugins = array(
			array('WP Force SSL', 'wp-force-ssl/wp-force-ssl.php'),
			array('WP SSL Redirect', 'wp-ssl-redirect/wp-ssl-redirect.php'),
			array('WP Encryption - One Click SSL', 'one-click-ssl/ssl.php'),
			array('WP Encryption', 'wp-letsencrypt-ssl/wp-letsencrypt.php'),
			array('Simple HTTPS Redirect', 'simple-https-redirect/index.php'),
			array('Redirection', 'redirection/redirection.php'),
			array('Really Simple SSL', 'really-simple-ssl/rlrsssl-really-simple-ssl.php'),
			array('JSM\'s Force HTTP to HTTPS', 'jsm-force-ssl/jsm-force-ssl.php'),
			array('Easy HTTPS (SSL) Redirection', 'https-redirection/https-redirection.php'),
		);
		$active_plugins = get_option('active_plugins');
		$conflicting_plugins = array();
		foreach($plugins as $plugin)
		{
			if(in_array($plugin[1], $active_plugins)) $conflicting_plugins[] = $plugin[0];
		}
		return $conflicting_plugins;
	}
	
	// check if .htaccess is present and writable
	function htaccess_writable() 
	{
		if(!stristr($_SERVER['SERVER_SOFTWARE'], 'apache') && !stristr($_SERVER['SERVER_SOFTWARE'], 'litespeed')) return false;
		if(is_writable(get_home_path().'.htaccess')) return true;
		return false;
	}
	
	// get siteurl hostname
	function siteurl_hostname()
	{
		return parse_url(get_option('siteurl'), PHP_URL_HOST);
	}
	
	// check if domain has SSL cert
	function has_ssl($domain)
	{
		
		// get cert
		$stream = @stream_context_create( array('ssl' => array('capture_peer_cert' => true)));
		$socket = @stream_socket_client('ssl://'. $domain.':443', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $stream);
		if($socket)
		{
			$cont = stream_context_get_params($socket);
			$cert_ressource = $cont['options']['ssl']['peer_certificate'];
			$cert = openssl_x509_parse($cert_ressource);
		}

		// check name
		if(isset($cert['name']))
		{
			$namepart = explode('=', $cert['name']);
			if(count($namepart) == 2)
			{
				$cert_domain = trim($namepart[1], '*. ');
				$check_domain = substr($domain, -strlen($cert_domain));
				if($cert_domain == $check_domain) return true;
			}
		}
		
		// check alternates
		if(isset($cert['extensions']['subjectAltName']))
		{
			$altnames = explode(', ', $cert['extensions']['subjectAltName']);
			for($i = 0; $i < count($altnames); $i++)
			{
				$altpart = explode(':', $altnames[$i]);
				if((count($altpart) == 2) && ($altpart[0] == 'DNS'))
				{
					$alt_domain = trim($altpart[1], '*. ');
					$check_domain = substr($domain, -strlen($alt_domain));
					if($alt_domain == $check_domain) return true;
				}
			}
		}
	
		return false;
		
	}
	
	// check siteurl and home
	function test_wp_urls()
	{
		return array(
			'siteurl' => (stripos(get_option('siteurl'), 'https://') === 0),
			'home' => (stripos(get_option('home'), 'https://') === 0)
		);
	}
	
	// flush cache(s!)
	function flush_caches()
	{
		wp_cache_flush();
		if(function_exists('w3tc_flush_all')) w3tc_flush_all();
		if(function_exists('w3tc_pgcache_flush')) w3tc_pgcache_flush();
		if(function_exists('wp_cache_clear_cache')) wp_cache_clear_cache();
		if(function_exists('wpfc_clear_all_cache')) wpfc_clear_all_cache();
		if(function_exists('rocket_clean_domain')) rocket_clean_domain();
		if(is_callable(array('SiteGround_Optimizer\Supercacher\Supercacher', 'purge_cache'))) SiteGround_Optimizer\Supercacher\Supercacher::purge_cache();
		if(is_callable(array('SG_CachePress_Supercacher', 'purge_cache'))) SG_CachePress_Supercacher::purge_cache(true);
		if(is_callable(array('LiteSpeed_Cache_API', 'purge_all'))) LiteSpeed_Cache_API::purge_all();
		if(is_callable(array('Hummingbird\WP_Hummingbird', 'flush_cache')))Hummingbird\WP_Hummingbird::flush_cache(true, false);
		if(is_callable(array('Swift_Performance_Cache', 'clear_all_cache')))Swift_Performance_Cache::clear_all_cache();
		if(is_callable(array('WpeCommon', 'purge_memcached'))) WpeCommon::purge_memcached();
		if(is_callable(array('WpeCommon', 'clear_maxcdn_cache'))) WpeCommon::clear_maxcdn_cache();
		if(is_callable(array('WpeCommon', 'purge_varnish_cache'))) WpeCommon::purge_varnish_cache();
		if(isset($GLOBALS['wp_fastest_cache']) && method_exists($GLOBALS['wp_fastest_cache'], 'deleteCache')) $GLOBALS['wp_fastest_cache']->deleteCache(true);
		if(class_exists('\Kinsta\Cache') && !empty($kinsta_cache)) $kinsta_cache->kinsta_cache_purge->purge_complete_caches();
		if(class_exists('Breeze_Admin')) do_action('breeze_clear_all_cache');
		if(defined('LSCWP_V')) do_action('litespeed_purge_all');
		if(function_exists('sg_cachepress_purge_cache')) sg_cachepress_purge_cache();
		if(class_exists('autoptimizeCache')) autoptimizeCache::clearall();
		if(class_exists('Cache_Enabler')) Cache_Enabler::clear_total_cache();
	}
	
	// ssl redirect
	function ssl_redirect_and_headers()
	{
		if(get_option('ssslr_method') == 'default')
		{
			$protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https" : "http";
			if($protocol !== 'https')
			{
				$url = sanitize_url('https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
				wp_safe_redirect($url, 301);
				exit;
			}
			if((get_option('ssslr_canonical_domain') == 'on') && $this::siteurl_hostname())
			{
				if($_SERVER['HTTP_HOST'] !== $this::siteurl_hostname())
				{
					$url = sanitize_url('https://'.$this::siteurl_hostname().$_SERVER['REQUEST_URI']);
					wp_safe_redirect($url, 301);
					exit;		
				}
			}
			if((get_option('ssslr_hsts') == 'on') && ($protocol == 'https'))
			{
				header('Strict-Transport-Security: max-age=31536000');
			}
		}
	}
	
}

// plugin object
$ssslr = new Simple_SSL_Redirects();

// register uninstall hook
register_uninstall_hook(__FILE__, 'Simple_SSL_Redirects::uninstall');

?>