<?php
define('DB_NAME', getenv('WORDPRESS_DB_NAME') ?: 'wordpress');
define('DB_USER', getenv('WORDPRESS_DB_USER') ?: 'wordpress');
define('DB_PASSWORD', getenv('WORDPRESS_DB_PASSWORD') ?: '');
define('DB_HOST', getenv('WORDPRESS_DB_HOST') ?: 'mariadb');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('SECURE_AUTH_KEY', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('LOGGED_IN_KEY', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('NONCE_KEY', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('AUTH_SALT', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('SECURE_AUTH_SALT', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('LOGGED_IN_SALT', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('NONCE_SALT', getenv('WORDPRESS_AUTH_KEY') ?: 'php2shell-demo');
define('WP_ENVIRONMENT_TYPE', 'local');
define('DISABLE_WP_CRON', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
$table_prefix = 'wp_';
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
