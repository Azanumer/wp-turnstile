<?php
/**
 * Plugin Name: WP Turnstile
 * Description: Adds Cloudflare Turnstile (privacy-friendly CAPTCHA) to the login, registration, lost-password, and comment forms. Server-side verification, no tracking cookies.
 * Version:     1.0.0
 * Author:      Azan Umer
 * License:     MIT
 * License URI: https://opensource.org/licenses/MIT
 * Text Domain: wp-turnstile
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WTS_VERSION', '1.0.0' );
define( 'WTS_OPTION', 'wts_settings' );
define( 'WTS_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify' );

/**
 * Get settings with defaults.
 *
 * @return array
 */
function wts_get_settings() {
    $defaults = array(
        'enabled'       => 0,
        'site_key'      => '',
        'secret_key'    => '',
        'theme'         => 'auto',
        'login'         => 1,
        'register'      => 1,
        'lostpassword'  => 1,
        'comments'      => 1,
    );
    return wp_parse_args( (array) get_option( WTS_OPTION, array() ), $defaults );
}

/**
 * Is Turnstile active for a given form and properly configured?
 *
 * @param string $form login|register|lostpassword|comments
 * @return bool
 */
function wts_active_for( $form ) {
    $s = wts_get_settings();
    return ! empty( $s['enabled'] )
        && ! empty( $s['site_key'] )
        && ! empty( $s['secret_key'] )
        && ! empty( $s[ $form ] );
}

/**
 * Enqueue the Turnstile script (only where a widget will be rendered).
 */
function wts_enqueue() {
    wp_enqueue_script(
        'cf-turnstile',
        'https://challenges.cloudflare.com/turnstile/v0/api.js',
        array(),
        null,
        true
    );
}

/**
 * Render the widget HTML.
 */
function wts_render_widget() {
    $s = wts_get_settings();
    printf(
        '<div class="cf-turnstile" data-sitekey="%s" data-theme="%s" style="margin:12px 0;"></div>',
        esc_attr( $s['site_key'] ),
        esc_attr( $s['theme'] )
    );
}

/**
 * Verify the Turnstile token against Cloudflare.
 *
 * @return bool
 */
function wts_verify() {
    $s = wts_get_settings();
    $token = isset( $_POST['cf-turnstile-response'] )
        ? sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) )
        : '';
    if ( '' === $token ) {
        return false;
    }
    $response = wp_remote_post( WTS_VERIFY_URL, array(
        'timeout' => 10,
        'body'    => array(
            'secret'   => $s['secret_key'],
            'response' => $token,
            'remoteip' => isset( $_SERVER['REMOTE_ADDR'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
                : '',
        ),
    ) );
    if ( is_wp_error( $response ) ) {
        return false;
    }
    $data = json_decode( wp_remote_retrieve_body( $response ), true );
    return is_array( $data ) && ! empty( $data['success'] );
}

/* -------------------------------------------------------------------------
 * Login form
 * ------------------------------------------------------------------------- */

function wts_login_render() {
    if ( ! wts_active_for( 'login' ) ) {
        return;
    }
    wts_enqueue();
    wts_render_widget();
}
add_action( 'login_form', 'wts_login_render' );

function wts_login_verify( $user, $username, $password ) {
    if ( ! wts_active_for( 'login' ) || is_wp_error( $user ) ) {
        return $user;
    }
    // Only challenge actual credential submissions, not empty-login probes.
    if ( '' === $username || '' === $password ) {
        return $user;
    }
    if ( ! wts_verify() ) {
        return new WP_Error(
            'turnstile_failed',
            __( '<strong>Error:</strong> Please complete the security check before logging in.', 'wp-turnstile' )
        );
    }
    return $user;
}
add_filter( 'authenticate', 'wts_login_verify', 30, 3 );

/* -------------------------------------------------------------------------
 * Registration form
 * ------------------------------------------------------------------------- */

function wts_register_render() {
    if ( ! wts_active_for( 'register' ) ) {
        return;
    }
    wts_enqueue();
    wts_render_widget();
}
add_action( 'register_form', 'wts_register_render' );

function wts_register_verify( $errors, $sanitized_user_login, $user_email ) {
    if ( wts_active_for( 'register' ) && ! wts_verify() ) {
        $errors->add(
            'turnstile_failed',
            __( '<strong>Error:</strong> Please complete the security check to register.', 'wp-turnstile' )
        );
    }
    return $errors;
}
add_filter( 'registration_errors', 'wts_register_verify', 10, 3 );

/* -------------------------------------------------------------------------
 * Lost password form
 * ------------------------------------------------------------------------- */

function wts_lostpassword_render() {
    if ( ! wts_active_for( 'lostpassword' ) ) {
        return;
    }
    wts_enqueue();
    wts_render_widget();
}
add_action( 'lostpassword_form', 'wts_lostpassword_render' );

function wts_lostpassword_verify( $errors, $user_data ) {
    if ( wts_active_for( 'lostpassword' ) && ! wts_verify() ) {
        $errors->add(
            'turnstile_failed',
            __( '<strong>Error:</strong> Please complete the security check before requesting a password reset.', 'wp-turnstile' )
        );
    }
}
add_action( 'lostpassword_post', 'wts_lostpassword_verify', 10, 2 );

/* -------------------------------------------------------------------------
 * Comment form
 * ------------------------------------------------------------------------- */

function wts_comment_render() {
    if ( ! wts_active_for( 'comments' ) || is_user_logged_in() ) {
        return;
    }
    wts_enqueue();
    wts_render_widget();
}
add_action( 'comment_form_after', 'wts_comment_render' );

function wts_comment_verify( $commentdata ) {
    if ( wts_active_for( 'comments' ) && ! is_user_logged_in() && ! wts_verify() ) {
        wp_die(
            esc_html__( 'Security check failed — please go back and complete the Turnstile challenge.', 'wp-turnstile' ),
            esc_html__( 'Comment rejected', 'wp-turnstile' ),
            array( 'response' => 403, 'back_link' => true )
        );
    }
    return $commentdata;
}
add_filter( 'preprocess_comment', 'wts_comment_verify' );

/* -------------------------------------------------------------------------
 * Admin settings
 * ------------------------------------------------------------------------- */

function wts_admin_menu() {
    add_options_page(
        __( 'Turnstile', 'wp-turnstile' ),
        __( 'Turnstile', 'wp-turnstile' ),
        'manage_options',
        'wts-settings',
        'wts_settings_page'
    );
}
add_action( 'admin_menu', 'wts_admin_menu' );

function wts_admin_init() {
    register_setting( 'wts_settings_group', WTS_OPTION, array(
        'sanitize_callback' => 'wts_sanitize',
    ) );
}
add_action( 'admin_init', 'wts_admin_init' );

/**
 * Sanitize settings on save.
 *
 * @param array $input
 * @return array
 */
function wts_sanitize( $input ) {
    $out = array();
    $out['enabled']      = ! empty( $input['enabled'] ) ? 1 : 0;
    $out['site_key']     = isset( $input['site_key'] ) ? sanitize_text_field( $input['site_key'] ) : '';
    $out['secret_key']   = isset( $input['secret_key'] ) ? sanitize_text_field( $input['secret_key'] ) : '';
    $out['theme']        = in_array( $input['theme'] ?? 'auto', array( 'auto', 'light', 'dark' ), true )
        ? $input['theme'] : 'auto';
    $out['login']        = ! empty( $input['login'] ) ? 1 : 0;
    $out['register']     = ! empty( $input['register'] ) ? 1 : 0;
    $out['lostpassword'] = ! empty( $input['lostpassword'] ) ? 1 : 0;
    $out['comments']     = ! empty( $input['comments'] ) ? 1 : 0;
    return $out;
}

function wts_settings_page() {
    $s = wts_get_settings();
    ?>
<div class="wrap">
  <h1><?php esc_html_e( 'Cloudflare Turnstile', 'wp-turnstile' ); ?></h1>
  <p><?php esc_html_e( 'Get your free keys at Cloudflare Dashboard → Turnstile. Use the "Testing" keys (1x00000000000000000000AA / 1x0000000000000000000000000000000AA) to try it without blocking real users.', 'wp-turnstile' ); ?></p>
  <form method="post" action="options.php">
    <?php settings_fields( 'wts_settings_group' ); ?>
    <table class="form-table">
      <tr>
        <th scope="row"><?php esc_html_e( 'Enable', 'wp-turnstile' ); ?></th>
        <td><label><input type="checkbox" name="<?php echo esc_attr( WTS_OPTION ); ?>[enabled]" value="1" <?php checked( $s['enabled'], 1 ); ?>>
        <?php esc_html_e( 'Enable Turnstile protection', 'wp-turnstile' ); ?></label></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Site key', 'wp-turnstile' ); ?></th>
        <td><input type="text" class="regular-text code" name="<?php echo esc_attr( WTS_OPTION ); ?>[site_key]" value="<?php echo esc_attr( $s['site_key'] ); ?>"></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Secret key', 'wp-turnstile' ); ?></th>
        <td><input type="password" class="regular-text code" name="<?php echo esc_attr( WTS_OPTION ); ?>[secret_key]" value="<?php echo esc_attr( $s['secret_key'] ); ?>" autocomplete="new-password"></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Theme', 'wp-turnstile' ); ?></th>
        <td>
          <select name="<?php echo esc_attr( WTS_OPTION ); ?>[theme]">
            <?php foreach ( array( 'auto', 'light', 'dark' ) as $theme ) : ?>
              <option value="<?php echo esc_attr( $theme ); ?>" <?php selected( $s['theme'], $theme ); ?>><?php echo esc_html( ucfirst( $theme ) ); ?></option>
            <?php endforeach; ?>
          </select>
        </td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Protect these forms', 'wp-turnstile' ); ?></th>
        <td>
          <?php foreach ( array( 'login' => 'Login', 'register' => 'Registration', 'lostpassword' => 'Lost password', 'comments' => 'Comment form (guests only)' ) as $key => $label ) : ?>
            <label style="display:block; margin-bottom:6px;">
              <input type="checkbox" name="<?php echo esc_attr( WTS_OPTION ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( $s[ $key ], 1 ); ?>>
              <?php echo esc_html( $label ); ?>
            </label>
          <?php endforeach; ?>
        </td>
      </tr>
    </table>
    <?php submit_button(); ?>
  </form>
</div>
    <?php
}
