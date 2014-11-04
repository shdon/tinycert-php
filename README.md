# TinyCert REST API Client Library for PHP #

## Description ##

This is the official PHP client library for the [TinyCert](https://www.tinycert.org/) [REST API](https://www.tinycert.org/docs/api).

## Requirements ##

This project requires PHP version 5.3 or greater with the cURL extension.

## Documentation ##

The source code is documented using the PHPDoc standard.

## Example usage ##

This is a brief example enumerating details of Certification Authorities and certificates in your account. Error checking is omitted for simplicity's sake:

```php
<?php
	require_once ('tinycert.inc.php');
	
	//Initiate a connection
	$tc = new TinyCert ('MySuperSecretApiKey');
	$tc->connect ('account@example.com', 'My Secret Passphrase');
	
	//Iterate over all CA's in the account
	$ca_list = $tc->ca_list ();
	foreach ($ca_list as $ca)
	{
		//Request CA details and dump to output
		$ca_details = $tc->ca_details ($ca ['id']);
		print_r ($ca_details);
		
		//Iterate over all certificates for this CA
		$cert_list = $tc->cert_list ($ca ['id'], TinyCert::STATUS_ALL);
		foreach ($cert_list as $cert)
		{
			//Request certificate details and dump to output
			$cert_details = $tc->cert_details ($cert ['id']);
			print_r ($cert_details);
		}
	}
	
	//Clean up nicely
	$tc->disconnect ();
```

## Copyright and License ##

This software is Copyright (c) 2014 by Steven Don / TinyCert.org

This is free software, licensed under the Simplified BSD license.
