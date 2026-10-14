<?php
/**
 * Uninstall cleanup for WP Turnstile.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'wts_settings' );
