versionscan
===========

[![Build Status](https://secure.travis-ci.org/psecio/versionscan.png?branch=master)](http://travis-ci.org/psecio/versionscan)

Versionscan is a tool for evaluating your currently installed PHP version
and checking it against known CVEs and the versions they were fixed in
to report back potential issues.

Installation
------------

### Using Composer

```
{
    "require": {
        "psecio/iniscan": "dev-master"
    }
}
```

The only current dependency is the Symfony console.

Usage
------------

To run the scan against your current PHP version, use:

`bin/versionscan`

The script will check the `PHP_VERSION` for the current instance and
generate the pass/fail results. The output looks similar to:

```
--------------------------------------------------
Status          | CVE ID              | Summary
--------------------------------------------------
PASS            | CVE-2013-6420       | PHP is an HTML-embedded scripting language commonly used with the Apache HTTP Server. A memory corruption flaw was found in the way the openssl_x509_parse() function of the PHP openssl extension parsed X.509 certificates. A remote attacker could use this flaw to provide a malicious self-signed certificate or a certificate signed by a trusted authority to a PHP application using the aforementioned function, causing the application to crash or, possibly, allow the attacker to execute arbitrary code with the privileges of the user running the PHP interpreter.
PASS            | CVE-2013-4248       | The openssl_x509_parse function in openssl.c in the OpenSSL module in PHP before 5.4.18 and 5.5.x before 5.5.2 does not properly handle a '\0' character in a domain name in the Subject Alternative Name field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority, a related issue to CVE-2009-2408.
```

Results will be reported back colorized as well to easily show the pass/fail
of the check.
