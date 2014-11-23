<?php
	/**
	 * @copyright 2014 TinyCert.org
	 * @license Simplified BSD
	 */
	class TinyCert
	{
		const CERTIFICATE = 'cert';
		const CERTIFICATE_CHAIN = 'chain';
		const HASH_SHA1 = 'sha1';
		const HASH_SHA256 = 'sha256';
		const PRIVKEY_DECRYPTED = 'key.dec';
		const PRIVKEY_ENCRYPTED = 'key.enc';
		const REQUEST = 'csr';
		const STATUS_EXPIRED = 1;
		const STATUS_GOOD = 2;
		const STATUS_REVOKED = 4;
		const STATUS_HOLD = 8;
		const STATUS_ALL = 15;
		
		private $apikey = NULL;
		private $ch = NULL;
		private $error = NULL;
		private $token = NULL;
		
		/**
		 * Create an instance of the TinyCert PHP API client.
		 *
		 * The required API key is generated on account creation and can be
		 * found on the profile page.
		 *
		 * @param string $apikey The API key associated with your TinyCert account.
		 */
		public function __construct ($apikey)
		{
			//Keep the API key for message signing
			$this->apikey = $apikey;
			
			//Set up a CURL handle to do requests
			$this->ch = curl_init ();
			curl_setopt_array
			(
				$this->ch,
				array
				(
					CURLOPT_HEADER => true,
					CURLOPT_POST => true,
					CURLOPT_RETURNTRANSFER => true
				)
			);
		}
		
		/**
		 * Internal method to prepare parameters for an API call, sign, and
		 * execute the request.
		 * 
		 * @param string $endpoint The endpoint for the requested API method.
		 * @param array $params An associative array of parameters for the API call.
		 * @return array|false The results of the API call on success, false on failure.
		 */		
		private function do_request ($endpoint, $params)
		{
			//Assume failure
			$rv = false;
			
			//Calculate SHA256 HMAC, append it to the body
			ksort ($params);
			$req = http_build_query ($params, '', '&');
			$hmac = hash_hmac ('sha256', $req, $this->apikey);
			$req .= '&digest=' . $hmac;
			
			//Pass parameters into the request
			curl_setopt_array
			(
				$this->ch,
				array
				(
					CURLOPT_URL => 'https://www.tinycert.org/api/v1' . $endpoint,
					CURLOPT_POSTFIELDS => $req
				)
			);
			
			//Carry out the actual request and parse the response for errors
			$resp = curl_exec ($this->ch);
			if ($resp)
			{
				list ($headers, $body) = explode ("\r\n\r\n", $resp);
				if (preg_match ('#^HTTP/\d\.\d (\d+) #', $headers, $m))
				{
					$status = intval ($m [1]);
					$data = json_decode ($body, true);
					if ($status === 200)
					{
						$this->error = NULL;
						$rv = $data;
					} else {
						$this->error = array
						(
							'status' => $status,
							'code' => $data ['code'],
							'text' => $data ['text']
						);
					}
				} else {
					$this->error = array
					(
						'status' -1,
						'code' => 'UnknownError',
						'text' => 'Invalid response from the API server'
					);
				}
			} else {
				$this->error = array
				(
					'status' -1,
					'code' => 'UnknownError',
					'text' => 'No response from the API server'
				);
			}
			
			return $rv;
		}
		
		/**
		 * Open a session on the TinyCert API server.
		 *
		 * @param string $email The email address associated with your account.
		 * @param string $passphrase The passphrase used to encrypt your private keys.
		 * @return bool True if the session was opened correctly, false on error.
		 */
		public function connect ($email, $passphrase)
		{
			$resp = $this->do_request ('/connect', array ('email' => $email, 'passphrase' => $passphrase));
			if ($resp)
			{
				$this->token = $resp ['token'];
				return true;
			} else {
				return false;
			}
		}
		
		/**
		 * Close the session on the TinyCert API server.
		 */
		public function disconnect ()
		{
			$this->do_request ('/disconnect', array ('token' => $this->token));
			$this->token = NULL;
		}
		
		/**
		 * Delete a Certification Authority (and all associated certificates).
		 *
		 * @param int $ca_id The ID of the Certification Authority to be deleted.
		 * @return bool True if the CA was successfully deleted, false on error.
		 */
		public function ca_delete ($ca_id)
		{
			return $this->do_request ('/ca/delete', array ('ca_id' => intval ($ca_id), 'token' => $this->token)) !== false;
		}
		
		/**
		 * Retrieve detailed description of a Certification Authority.
		 *
		 * The returned array contains the following indices:
		 * - id: Identifier for the CA (same as the $ca_id input).
		 * - C: ISO 3166-1 alpha-2 country code.
		 * - ST: State or province name.
		 * - L: Locality (city or town) name.
		 * - O: Organisation name.
		 * - OU: Organisational Unit name (always "Secure Digital Certificate Signing")
		 * - CN: Common Name (always the Organisation Name followed by " CA")
		 * - E: Email address (the address associated with your account when it was created)
		 * - hash_alg: The hashing algorithm, either "SHA1" or "SHA256"
		 *
		 * @param int $ca_id The ID of the Certification Authority to get the description for.
		 * @return array|false An associative array with details about the CA, false on error.
		 */
		public function ca_details ($ca_id)
		{
			return $this->do_request ('/ca/details', array ('ca_id' => intval ($ca_id), 'token' => $this->token));
		}
		
		/**
		 * Retrieve the Certification Authority certificate.
		 *
		 * The certificate itself is in PEM encoded form, just as if it had been
		 * downloaded from the TinyCert dashboard. It can be dumped directly to
		 * a .pem file.
		 *
		 * @param int $ca_id The ID of the Certification Authority for which to retrieve the certificate.
		 * @param string $what Reserved. Must always have the value of TinyCert::CERTIFICATE
		 * @return string|false A string with the PEM encoded certificate, false on error.
		 */
		public function ca_get ($ca_id, $what)
		{
			$resp = $this->do_request ('/ca/get', array ('ca_id' => intval ($ca_id), 'token' => $this->token, 'what' => $what));
			return $resp ? $resp ['pem'] : false;
		}
		
		/**
		 * Retrieve a list of all Certification Authorities associated with the account.
		 *
		 * The list of Certification Authorities is represented as an array of
		 * associative arrays that have the following indices:
		 * - id: Numeric CA identifier that may be used in other calls to the API.
		 * - name: Value of the Organisation Name on the certificate.
		 *
		 * @return array|false Array of CA records, false on error.
		 */
		public function ca_list ()
		{
			return $this->do_request ('/ca/list', array ('token' => $this->token));
		}
		
		/**
		 * Create a new Certification Authority.
		 *
		 * @param string $O Organisation Name for human identification of the CA.
		 * @param string $L Locality (city or town).
		 * @param string $ST State or province name.
		 * @param string $C ISO 3166-1 alpha-2 country code.
		 * @param string $hash_method The hashing algorithm, either TinyCert::HASH_SHA1 or TinyCert::HASH_SHA256.
		 * @return int|false An integer identifier of the newly created CA to be used in other API calls, false on error.
		 */
		public function ca_new ($O, $L, $ST, $C, $hash_method)
		{
			$resp = $this->do_request
			(
				'/ca/new',
				array
				(
					'C' => $C,
					'L' => $L,
					'O' => $O,
					'ST' => $ST,
					'hash_method' => $hash_method,
					'token' => $this->token
				)
			);
			return $resp ? intval ($resp ['ca_id']) : false;
		}
		
		/**
		 * Retrieve detailed description of a certificate.
		 *
		 * The returned array contains the following indices:
		 * - id: Identifier for the certificate (same as the $cert_id input).
		 * - status: One of "good", "hold", "expired", "revoked", or "obsolete".
		 * - C: ISO 3166-1 alpha-2 country code.
		 * - ST: State or province name.
		 * - L: Locality (city or town) name.
		 * - O: Organisation name.
		 * - OU: Organisational Unit name.
		 * - CN: Common Name.
		 * - Alt: An array of SANs, or NULL if none were specified.
		 * If the Alt field is an array, each record will be an associative
		 * array with one key, defining the type (one of "DNS", "email", "IP",
		 * or "URI") and its value being the corresponding name.
		 *
		 * @param int $cert_id The ID of the certificate to get the description for.
		 * @return array|false An associative array with details about the certificate, false on error.
		 */
		public function cert_details ($cert_id)
		{
			return $this->do_request ('/cert/details', array ('cert_id' => intval ($cert_id), 'token' => $this->token));
		}
		
		/**
		 * Retrieve the actual certificate, signing request or private key.
		 *
		 * The returned data is in PEM encoded form, just as if it had been
		 * downloaded from the TinyCert dashboard. It can be dumped directly to
		 * a .pem file.
		 *
		 * @param int $cert_id The ID of the certificate for which to retrieve the certificate, signing request or private key.
		 * @param string $what Used to select which data to retrieve. One of TinyCert::CERTIFICATE, TinyCert::CERTIFICATE_CHAIN, TinyCert::REQUEST, TinyCert::PRIVKEY_DECRYPTED, TinyCert::PRIVKEY_ENCRYPTED
		 * @return string|false A string with the PEM encoded certificate, signing request or private key, false on error.
		 */
		public function cert_get ($cert_id, $what)
		{
			$resp = $this->do_request ('/cert/get', array ('cert_id' => intval ($cert_id), 'token' => $this->token, 'what' => $what));
			return $resp ? $resp ['pem'] : false;
		}
		
		/**
		 * Retrieve a list of certificates associated with a given Certification Authority.
		 *
		 * The list of certificates is represented as an array of
		 * associative arrays that have the following indices:
		 * - id: Numeric certificate identifier that may be used in other calls to the API.
		 * - name: Value of the Common Name on the certificate.
		 * - status: One of "good", "hold", "expired", or "revoked".
		 * - expires: Unix timestamp of the certificate's expiration.
		 *
		 * The $what parameter determines which certificates are included in
		 * the returned list, filtering by their status. Use bitwise OR to
		 * combine TinyCert::STATUS_GOOD, TinyCert::STATUS_HOLD,
		 * TinyCert::STATUS_EXPIRED, and TinyCert::STATUS_REVOKED. To
		 * retrieve all available certificates, use TinyCert::STATUS_ALL for
		 * convenience.
		 *
		 * @param int $ca_id The ID of the Certification Authority for which to retrieve the list of certificates.
		 * @param int $what Used to include only certificates with any of the given statuses.
		 * @return array|false Array of certificate records, false on error.
		 */
		public function cert_list ($ca_id, $what)
		{
			return $this->do_request ('/cert/list', array ('ca_id' => intval ($ca_id), 'token' => $this->token, 'what' => $what));
		}
		
		/**
		 * Create a new signing request and generate a corresponding certificate.
		 *
		 * Subject Alternate Names (SANs), if desired, must be specified using
		 * the same format as returned by the cert_details method. That is:
		 * a numerically indexed (zero-based) array. Each array element must
		 * represent a single SAN as an associative array whith a single
		 * element. The key determines the type of SAN and must be one of
		 * "DNS", "IP", "email", or "URI" (case sensitive). The corresponding
		 * value is the actual name.
		 *
		 * @param int $ca_id The ID of the Certificate Authority to be used to sign the certificate.
		 * @param string $CN Common Name on the certificate.
		 * @param string $OU Organisational Unit name.
		 * @param string $O Organisation name.
		 * @param string $L Locality (city or town).
		 * @param string $ST State or province name.
		 * @param string $C ISO 3166-1 alpha-2 country code.
		 * @param array|NULL $SANs An array of Subject Alternate Names, or NULL if none are required.
		 * @return int|false An integer identifier of the newly created certificate to be used in other API calls, false on error.
		 */
		public function cert_new ($ca_id, $CN, $OU, $O, $L, $ST, $C, $SANs)
		{
			$params = array
			(
				'C' => $C,
				'CN' => $CN,
				'L' => $L,
				'O' => $O,
				'OU' => $OU,
				'SANs' => $SANs,
				'ST' => $ST,
				'ca_id' => intval ($ca_id),
				'token' => $this->token
			);
			if (!is_array ($SANs) || !count ($SANs)) unset ($params ['SANs']);
			$resp = $this->do_request ('/cert/new', $params);
			return $resp ? intval ($resp ['cert_id']) : false;
		}
		
		/**
		 * Reissue the certificate.
		 *
		 * Reissuing a certificate looks up the request from which the given
		 * certificate was generated and generates a new certificate with the
		 * same values, valid for one year from the time the reissue request
		 * was made.
		 *
		 * If the status of the original certificate was "good", it will
		 * automatically be changed to "obsolete". Subsequent requests should
		 * no longer be made using that certificate ID.
		 *
		 * If this method call completes successfully, it will return the ID of
		 * the newly generated certificate. This can then be passed on to other
		 * API calls, such as cert_details, cert_get, and cert_status.
		 *
		 * @param int $cert_id The ID of the certificate to reissue.
		 * @return int|false The new certificate's identifier on success, false on error.
		 */
		public function cert_reissue ($cert_id)
		{
			$resp = $this->do_request ('/cert/reissue', array ('cert_id' => intval ($cert_id), 'token' => $this->token));
			return $resp ? intval ($resp ['cert_id']) : false;
		}
		
		/**
		 * Change the status of a certificate.
		 *
		 * The status of a certificate can be changed only if the certificate
		 * currently has a status of "good", "revoked", or "hold" and can only
		 * be changed to another one of those 3 statuses. It is not possible
		 * to change the status for certificates that are marked as "expired"
		 * or "obsolete".
		 *
		 * If the current status already is the desired status, the request
		 * is ignored and reported as having completed successfully.
		 *
		 * @param int $cert_id The ID of the certificate for which the status should be changed.
		 * @param string $status The desired new status of the certificate. One of "good", "revoked", or "hold".
		 * @return bool True on success, false on error.
		 */
		public function cert_status ($cert_id, $status)
		{
			return $this->do_request ('/cert/status', array ('cert_id' => intval ($cert_id), 'status' => $status, 'token' => $this->token)) !== false;
		}
		
		/**
		 * Retrieve details on the error condition encountered in the most recent API call.
		 *
		 * The returned associative array contains the following indices:
		 * - status: The HTTP status code returned, or -1 if no valid status code was returned.
		 * - code: A short string describing the type of error.
		 * - text: A longer textual description of the error, containing further details.
		 *
		 * HTTP status codes returned on error can be any of the following:
		 * - 400: An input parameter is missing or invalid, or the API call did not meet the API requirements.
		 * - 403: Your session is not properly authenticated, or you do not have access to the requested resource.
		 * - 404: The API cannot find the resource you requested, which may occur when an invalid ID is specified.
		 * - 429: You have exceeded the rate limit on certain API calls.
		 * - 500: Unexpected situations encountered by the API server.
		 *
		 * The short error code can be any of the following:
		 * - AccessDenied: The requested resource is not associated with this account.
		 * - AccountError: Account data is corrupt. Please contact support.
		 * - AccountNotFound: No account exists for the specified email address.
		 * - AccountNotLoaded: There was an unexpected error loading the account data. Please contact support.
		 * - ApiKeyMismatch: The API key specified is not valid for the requested account.
		 * - InputFailure: An invalid value was specified for one of the input parameters.
		 * - InvalidToken: The token does not correspond to a valid session or has expired.
		 * - MethodDisallowed: All API calls must be made using the POST request method.
		 * - MissingParameter: A required parameter is missing.
		 * - NotFound: The requested resource was not found. Check that the specified ID is valid.
		 * - NotLatest: Attempting to reissue a certificate from an obsolete ID.
		 * - PassphraseFailure: The passphrase specified is incorrect.
		 * - RateLimitExceeded: You are attempting to create new CAs or certificates too rapidly.
		 * - SessionError: The session was not properly initialised.
		 * - SignatureFailure: The request was not properly signed.
		 * - StatusDisallowed: An invalid status change was requested for a certificate.
		 * - UnknownError: Generic fatal error condition. Please contact support.
		 * 
		 * Proper implementations should never encounter errors such as
		 * MethodDisallowed or SignatureFailure. They are included in the list
		 * above for completeness.
		 * 
		 * @return array|null Array of error details if the previous API call resulted in failure, NULL if that call was successful.
		 */
		public function last_error ()
		{
			return $this->error;
		}
	}
