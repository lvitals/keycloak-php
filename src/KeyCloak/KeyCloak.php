<?php

namespace Lvitals\KeyCloak;

class KeyCloak {

	public $grant;

	public $realm_id;
	protected $client_id;
	protected $secret;
	protected $auth_server_url;

	protected $realm_url;
	protected $realm_admin_url;

	protected $public_key;
	protected $is_public;

	private $config;

	/**
	 * Construct a grant manager.
	 *
	 * @param {Array|JSON String} $config config data.
	 *
	 * @constructor
	 */
	public function __construct ($config_data) {

		$this->config = file_get_contents($config_data);

		if (gettype($this->config) === 'string') {
			$this->config = json_decode($this->config, true);
		}

		/**
		 * Realm ID
		 * @type {String}
		 */
		$this->realm_id = $this->config['realm'];

		/**
		 * Client/Application ID
		 * @type {String}
		 */
		$this->client_id = array_key_exists('resource', $this->config) ? $this->config['resource'] : $this->config['client_id'];

		/**
		 * If this is a public application or confidential.
		 * @type {String}
		 */
		$this->is_public = array_key_exists('public-client', $this->config) ? $this->config['public-client'] : FALSE;

		/**
		 * Client/Application secret
		 * @type {String}
		 */
		if (!$this->is_public) {
			$this->secret = array_key_exists('credentials', $this->config) ? $this->config['credentials']['secret'] : (array_key_exists('secret', $this->config) ? $this->config['secret'] : NULL);
		}

		/**
		 * Authentication server URL
		 * @type {String}
		 */
		$this->auth_server_url = $this->config['auth-server-url'] ? $this->config['auth-server-url'] : FALSE;

		/**
		 * Root realm URL.
		 * @type {String}
		 */
		$this->realm_url = $this->auth_server_url . '/realms/' . $this->realm_id;

		/**
		 * Root realm admin URL.
		 * @type {String}
		 */
		$this->realm_admin_url = $this->auth_server_url . '/admin/realms/' . $this->realm_id;

		/**
		 * Formatted public-key.
		 * @type {String}
		 */
		// $key_parts = str_split($config_data['realm-public-key'], 64);
		// $this->public_key = "-----BEGIN PUBLIC KEY-----\n" . implode("\n", $key_parts) . "\n-----END PUBLIC KEY-----\n";
	}

	protected function base_url_user($path) {
		return $this->realm_url . $path;
	}

	protected function base_url_admin($path) {
		return $this->realm_admin_url . $path;
	}

	/**
	 * Use the direct grant API to obtain a grant from Keycloak.
	 *
	 * The direct grant API must be enabled for the configured realm
	 * for this method to work. This function ostensibly provides a
	 * non-interactive, programatic way to login to a Keycloak realm.
	 *
	 * This method can either accept a callback as the last parameter
	 * or return a promise.
	 *
	 * @param {String} $username The username.
	 * @param {String} $password The cleartext password.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_login ($username, $password) {
		$payload = array(
			'grant_type' => 'password',
			'username' => $username,
			'password' => $password
		);

		$headers = array(
		    'Content-type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$payload['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}

		$response = $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/token'), $headers, http_build_query($payload));

		if (!array_key_exists('code_error', json_decode($response, true))) {
			$this->grant = new Grant($response);
			return $response;
		} else {
			$this->grant = null;
			return false;
		}
	}

	/**
	 * Obtain a grant from a previous interactive login which results in a code.
	 *
	 * This is typically used by servers which receive the code through a
	 * redirect_uri when sending a user to Keycloak for an interactive login.
	 *
	 * An optional session ID and host may be provided if there is desire for
	 * Keycloak to be aware of this information.  They may be used by Keycloak
	 * when session invalidation is triggered from the Keycloak console itself
	 * during its postbacks to `/k_logout` on the server.
	 *
	 * This method returns or promise or may optionally take a callback function.
	 *
	 * @param {String} $code The code from a successful login redirected from Keycloak.
	 * @param {String} $session_id Optional opaque session-id.
	 * @param {String} $session_host Optional session host for targetted Keycloak console post-backs.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_code ($code, $redirect_uri = '', $session_host = NULL) {
		$payload = array(
			'grant_type' => 'authorization_code',
			'code' => $code,
			'client_id' => $this->client_id
		);

		if (!empty($redirect_uri)) {
			$payload['redirect_uri'] = $redirect_uri;
		}

		if ($session_host) {
			$payload['application_session_host'] = $session_host;
		}

		$headers = array(
		    'Content-Type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$payload['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}

		$response = $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/token'), $headers, http_build_query($payload));

		if (!array_key_exists('code_error', json_decode($response, true))) {
			$this->grant = new Grant($response);
			return $response;
		} else {
			$this->grant = null;
			return false;
		}
	}

	/**
	 * Restore a grant that has been saved in the session.
	 *
	 * This is typically used by server after the user has already logged on
	 * and the grant saved in the session.
	 *
	 * This method returns or promise or may optionally take a callback function.
	 *
	 * @param {String} $code The code from a successful login redirected from Keycloak.
	 * @param {String} $session_id Optional opaque session-id.
	 * @param {String} $session_host Optional session host for targetted Keycloak console post-backs.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_data ($grant_data) {
		$this->grant = new Grant($grant_data);

		$success = $this->validate_grant();

		if (!$success) {
			return $this->refresh_grant();
		}

		return true;
	}


	/**
	 * Get info users.
	 *
	 * This is typically used by server after the user has already logged on
	 * and the grant saved in the session.
	 *
	 * This method returns or promise or may optionally take a callback function.
	 *
	 * @param {String} $code The code from a successful login redirected from Keycloak.
	 * @param {String} $session_id Optional opaque session-id.
	 * @param {String} $session_host Optional session host for targetted Keycloak console post-backs.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */

	public function get_userinfo ($grant_data) {
		$this->grant = new Grant($grant_data);

		$success = $this->validate_grant();

		if (!$success) {
			return false;
		}

		return $this->grant->access_token;
	}

	/**
	 * Ensure that a grant is *fresh*, refreshing if required & possible.
	 *
	 * If the access_token is not expired, the grant is left untouched.
	 *
	 * If the access_token is expired, and a refresh_token is available,
	 * the grant is refreshed, in place (no new object is created),
	 * and returned.
	 *
	 * If the access_token is expired and no refresh_token is available,
	 * an error is provided.
	 *
	 * The method may either return a promise or take an optional callback.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	protected function refresh_grant () {
		// Ensure grant exists, grant is not expired, and we have a refresh token
		if (!$this->grant || $this->grant->is_expired() || !$this->grant->refresh_token) {
			$this->grant = null;
			return false;
		}

		$payload = array(
			'grant_type' => 'refresh_token',
			'refresh_token' => $this->grant->refresh_token->to_string()
		);

		$headers = array(
			'Content-type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$payload['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}

		$response = $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/token'), $headers, http_build_query($payload));

		if (!array_key_exists('code_error', json_decode($response, true))) {
			$this->grant = new Grant($response);
			return $response;
		} else {
			$this->grant = null;
			return false;
		}
	}

	/**
	 * Validate the grant and all tokens contained therein.
	 *
	 * This method filters a grant (in place), by nulling out
	 * any invalid tokens.  After this method returns, the
	 * passed in grant will only contain valid tokens.
	 *
	 */
	protected function validate_grant () {
		return ($this->grant->access_token && $this->grant->refresh_token) ? true : false;
	}

	/**
	 * Get the account information associated with the token
	 *
	 * This method accepts a token, and either returns the
	 * user account information, or it returns NULL
	 * if it encourters error:
	 *
	 * @return {Array} An array that contains user account info, or NULL
	 */
	public function get_account () {
		$headers = array(
				'Authorization: Bearer ' . $this->grant->access_token->to_string(),
				'Accept: application/json'
		);

		return $this->send_request('GET', $this->base_url_user('/protocol/openid-connect/userinfo'), $headers);
	}

	/**
	 * Get the introspection information associated with the token
	 *
	 * This method accepts a token, and either returns the
	 * user account information, or it returns NULL
	 * if it encourters error:
	 *
	 * @return {Array} An array that contains user account info, or NULL
	 */
	public function get_token_introspection ($token) {

		if ($this->isJson($token)) {
			$token = json_decode($token, true);
			$token = (array_key_exists('access_token', $token)) ? $token['access_token'] : null;
		}

		$payload = array(
			'client_id' => $this->config['resource'],
			'client_secret' => $this->config['credentials']['secret'],
			'token' => $token
		);

		$payload = http_build_query($payload);

		$headers = array(
			'Content-Type: application/x-www-form-urlencoded'
		);

		return $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/token/introspect'), $headers, $payload);

	}

	public function get_token_by_refresh_token ($refresh_token = '') {

		if ($refresh_token == '') {
			$refresh_token = $this->grant->refresh_token->to_string();
		}

		$payload = array(
			'client_id' => $this->config['resource'],
			'client_secret' => $this->config['credentials']['secret'],
			'grant_type' => 'refresh_token',
			'refresh_token' => $refresh_token
		);

		$payload = http_build_query($payload);

		$headers = array(
			'Content-Type: application/x-www-form-urlencoded'
		);

		return $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/token'), $headers, $payload);

	}

	public function logout($refresh_token = '') {

		if ($refresh_token == '') {
			$refresh_token = $this->grant->refresh_token->to_string();
		}

		$payload = array(
			'client_id' => $this->config['resource'],
			'client_secret' => $this->config['credentials']['secret'],
			'grant_type' => 'refresh_token',
			'refresh_token' => $refresh_token
		);

		$payload = http_build_query($payload);

		$headers = array(
			'Content-Type: application/x-www-form-urlencoded'
		);

	  return  $this->send_request('POST', $this->base_url_user('/protocol/openid-connect/logout'), $headers, $payload);

	}

	/**
	 * Administrator users
	 * 
	 */

	public function create_user($user_representation, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json",
			"Content-Type:application/json"
		);
		
		return $this->send_request('POST', $this->base_url_admin('/users'), $headers, json_encode($user_representation));
	}

	public function update_user($id, $user_representation, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json",
			"Content-Type:application/json"
		);

		return $this->send_request('PUT', $this->base_url_admin("/users/{$id}"), $headers, json_encode($user_representation));
	}


	public function delete_user($id, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json",
			"Content-Type:application/json"
		);

		return $this->send_request('DELETE', $this->base_url_admin("/users/{$id}"), $headers);
	}

	public function get_users($access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin('/users'), $headers);
	}


	public function count_users($access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin('/users/count/'), $headers);
	}

	public function get_user($id, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin("/users/{$id}"), $headers);
	}

	public function get_groups($access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin('/groups'), $headers);
	}

	public function get_clients($access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin('/clients'), $headers);
	}

	public function get_role_mappings($id, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin("/users/{$id}/role-mappings"), $headers);
	}

	public function get_roles_client_by_name($id, $role_name, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin("/clients/{$id}/roles/{$role_name}"), $headers);
	}

	public function get_all_roles_client($id, $access_token) {

		$headers = array(
			"Authorization: Bearer {$access_token}",
			"Accept: application/json"
		);
	
		return $this->send_request('GET', $this->base_url_admin("/clients/{$id}/roles"), $headers);
	}

	/**
	* Various URL getters
	*/
	public function login_url ($redirect_uri) {
		$uuid = bin2hex(openssl_random_pseudo_bytes(32));
    	return $this->realm_url . '/protocol/openid-connect/auth?client_id=' . KeyCloak::encode_uri_component($this->client_id) . '&state=' . KeyCloak::encode_uri_component($uuid) . '&redirect_uri=' . KeyCloak::encode_uri_component($redirect_uri) . '&response_type=code';
	}

	public function logout_url ($redirect_uri) {
		return $this->realm_url . '/protocol/openid-connect/logout?redirect_uri=' . KeyCloak::encode_uri_component($redirect_uri);
	}

	public function account_url ($redirect_uri) {
		return $this->realm_url . '/account' . '?referrer=' . KeyCloak::encode_uri_component($this->client_id) . '&referrer_uri=' . KeyCloak::encode_uri_component($redirect_uri);
	}

	/**
	* Send HTTP request via CURL
	*
	* @param {String} $method The HTTP request to use. (Default to GET)
	* @param {String} $path The path that follows $this->realm_url, can include GET params
	* @param {Array} $headers The HTTP headers to be passed into the request
	* @param {String} $data The data to be passed into the body of the request
	*
	* @return {Array} An associative array with 'code' for response code and 'body' for request body
	*/
	protected function send_request ($method = 'GET', $url = '', $headers = array(), $data = '') {
		
		$method = strtoupper($method);

		// Initiate HTTP request
		$request = curl_init();

		if ($method === 'POST' || $method === 'PUT') {
			curl_setopt($request, CURLOPT_POST, true);
			curl_setopt($request, CURLOPT_POSTFIELDS, $data);
			array_push($headers, 'Content-Length: ' . strlen($data));
		}

		curl_setopt($request, CURLOPT_URL, $url);
		curl_setopt($request, CURLOPT_CUSTOMREQUEST, $method);
		curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($request, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($request, CURLOPT_TIMEOUT, 30); 

		$response = curl_exec($request);
		$response_code = curl_getinfo($request, CURLINFO_HTTP_CODE);
		curl_close($request);

		if ($response_code < 200 || $response_code > 299) {
			return json_encode(
				array_merge(array('code_error' => $response_code),
										json_decode($response, true))
			);
		}

		return $response;
	}

	/**
	 * PHP version of Javascript's encodeURIComponent that doesn't covert every character
	 *
	 * @param {String} $str The string to be encoded.
	 */
	public static function encode_uri_component ($str) {
		$revert = array(
				'%21' => '!',
				'%2A' => '*',
				'%27' => "'",
				'%28' => '(',
				'%29' => ')'
		);
		return strtr(rawurlencode($str), $revert);
	}

	/**
	* Decode a string with URL-safe Base64.
	*
	* @param string $input A Base64 encoded string
	*
	* @return string A decoded string
	*/
	public static function url_base64_decode ($input) {
			$remainder = strlen($input) % 4;
			if ($remainder) {
				$padlen = 4 - $remainder;
				$input .= str_repeat('=', $padlen);
			}
			return base64_decode(strtr($input, '-_', '+/'));
	}

	/**
	* Encode a string with URL-safe Base64.
	*
	* @param string $input The string you want encoded
	*
	* @return string The base64 encode of what you passed in
	*/
	public static function url_base64_encode ($input) {
		return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
	}

	/**
	* Check is Json.
	*
	* @param string $input The string you want encoded
	*
	* @return {Boolean} TRUE for success or FALSE for failure
	*/
	public static function isJson($string) {
		json_decode($string);
		return (json_last_error() == JSON_ERROR_NONE);
	}


}
