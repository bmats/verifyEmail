<?php

class EmailVerifier {
    /**
     * Check the syntax of the email.
     */
    const CHECK_SYNTAX     = 0x01;

    /**
     * Check whether the domain is on a list of disposable domains.
     */
    const CHECK_DISPOSABLE = 0x02;

    /**
     * Check whether DNS records for the email domain exist.
     */
    //const CHECK_DNS        = 0x04;

    /**
     * Check whether it is possible to connect to the SMTP server.
     */
    //const CHECK_SMTP       = 0x08;

    /**
     * Check whether the mailbox is reported to be valid by the mail server.
     */
    //const CHECK_MAILBOX    = 0x10;

    /**
     * Check whether the mail server reports all mailboxes as valid.
     */
    const CHECK_ACCEPT_ALL = 0x20;

    /**
     * Check all of the above.
     */
    const CHECK_EVERYTHING = 0x3F;

    const RESULT_BAD_SYNTAX     = 'syntax';
    const RESULT_DISPOSABLE     = 'disposable';
    const RESULT_NO_MX_RECORDS  = 'no_mx_records';
    const RESULT_INVALID_DOMAIN = 'invalid_domain';
    const RESULT_SMTP_FAIL      = 'smtp_fail';
    const RESULT_ACCEPT_ALL     = 'accept_all';
    const RESULT_INVALID        = 'invalid';
    const RESULT_VALID          = 'valid';

    private $checks         = self::CHECK_EVERYTHING;
    private $fromAddress    = 'test@example.com';
    private $connectTimeout = 60;
    private $slow           = true;
    private $slowDelay      = 1;
    private $debug          = false;

    private $acceptAllPrefix;
    private $disposableDomains = null;
    private $resolvedDomains = array();

    public function __construct() {
        $this->acceptAllPrefix = self::getRandomString();
    }

    /**
     * Set the checks that should be performed by verification. Or (|) together the EmailVerifier::CHECK_* flags, or use EmailVerifier::CHECK_EVERYTHING.
     * @param int $flags The check flags.
     */
    public function setChecks($flags) {
        $this->checks = $flags;
    }

    /**
     * Get the checks that are performed during verification. Default EmailVerifier::CHECK_EVERYTHING.
     * @return int The check flags.
     */
    public function getChecks() {
        return $this->checks;
    }

    /**
     * Set the email address that should be specified as the FROM address when connecting to SMTP servers.
     * @param string $address A valid email address.
     */
    public function setFromAddress($address) {
        $this->fromAddress = $address;
    }

    /**
     * Get the email address used as the FROM address. Default "test@example.com".
     * @return string The email address.
     */
    public function getFromAddress() {
        return $this->fromAddress;
    }

    /**
     * Set the connection timeout used when connecting to email servers.
     * @param int $timeout The timeout, in seconds.
     */
    public function setConnectTimeout($timeout) {
        $this->connectTimeout = $timeout;
    }

    /**
     * Get the connection timeout used when connecting. Default 60.
     * @return int The timeout, in seconds.
     */
    public function getConnectTimeout() {
        return $this->connectTimeout;
    }

    /**
     * Enable or disable slow verify mode. This slows down the verification, but will help prevent the verification looking like spam.
     * @param bool $on Slow mode enabled?
     */
    public function setSlow($on) {
        $this->slow = $on;
    }

    /**
     * Get whether slow verify mode is enabled. Default true.
     * @return bool Slow mode enabled?
     */
    public function getSlow() {
        return $this->slow;
    }

    /**
     * Set the delay between subsequent connections to the same server when slow mode is enabled.
     * @param float $delay The delay, in seconds.
     */
    public function setSlowDelay($delay) {
      $this->slowDelay = $delay;
    }

    /**
     * Get the delay between connections in slow mode.
     * @return float The delay, in seconds.
     */
    public function getSlowDelay() {
      return $this->slowDelay;
    }

    /**
     * Set whether debug info should be printed. Default false.
     * @param bool $on Debug mode on?
     */
    public function setDebug($on) {
        $this->debug = $on;
    }

    /**
     * Verify a a bunch of email addresses.
     * @param  string[] $emails The emails to verify
     * @return array            An array having the emails as the keys and the verify results (one of the EmailVerifier::RESULT_* constants) as the values.
     */
    public function verify($emails) {
        $results = array();

        // Group the emails by domain so we can query a domain all at once
        $domains = array();
        foreach ($emails as $email) {
            $email = trim($email);

            if ($this->checks & self::CHECK_SYNTAX) {
                // Check the email syntax
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $results[$email] = self::RESULT_BAD_SYNTAX;
                    continue;
                }
            }

            // Extract the domain
            $parts = explode('@', $email);
            $domain = $parts[1];
            $domain = strtolower($domain);

            // Trim [ and ] from beginning and end of domain string, respectively
            $domain = ltrim($domain, '[');
            $domain = rtrim($domain, ']');

            if ('IPv6:' === substr($domain, 0, strlen('IPv6:'))) {
                $domain = substr($domain, strlen('IPv6') + 1);
            }

            $domains[$domain][] = $email;
        }

        foreach ($domains as $domain => $emails) {
            // Check if this domain is disposable
            if ($this->checks & self::CHECK_DISPOSABLE) {
                if ($this->disposableDomains === null)
                    $this->disposableDomains = self::loadFile(dirname(__FILE__) . '/disposable.txt');

                if (in_array($domain, $this->disposableDomains)) {
                    if ($this->debug)
                        echo "$domain is disposable.\n";

                    foreach ($emails as $email)
                        $results[$email] = self::RESULT_DISPOSABLE;
                    continue;
                }
            }

            $connect = null;
            $host    = null;

            // Try using a previously successful host
            if (isset($this->resolvedDomains[$domain])) {
                $host = $this->resolvedDomains[$domain];
                $connect = @fsockopen($host, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);
            }

            if (!isset($connect) || !$connect) {
                $mxHosts = $this->getHosts($domain);

                // If there no hosts, fail
                if (empty($mxHosts)) {
                    if ($this->debug)
                        echo "No MX records for $domain.\n";

                    foreach ($emails as $email)
                        $results[$email] = self::RESULT_NO_MX_RECORDS;
                    continue;
                }

                // Try connecting to each host in order, and use the first host which succeeds
                foreach ($mxHosts as $host) {
                    $connect = @fsockopen($host, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);

                    if ($connect) {
                        $this->resolvedDomains[$domain] = $host;
                        break;
                    }
                    else if ($this->debug) {
                        if (!isset($connectErrNo) || $connectErrNo === 0)
                            echo "Could not connect to $host ($domain): error opening socket\n";
                        else
                            echo "Could not connect to $host ($domain): $connectErrStr ($connectErrNo)\n";
                    }
                }
            }

            // If all connections failed, fail
            if (!$connect) {
                foreach ($emails as $email)
                    $results[$email] = self::RESULT_INVALID_DOMAIN;
                continue;
            }

            if ($this->checks & self::CHECK_ACCEPT_ALL) {
                // Check if a random mailbox is accepting
                $acceptAllResult = array();
                $this->checkMailboxes($connect, array( $this->acceptAllPrefix . '@' . $domain ), $acceptAllResult, $host, $domain);

                if (array_pop($acceptAllResult) === self::RESULT_VALID) {
                    if ($this->debug)
                        echo "$domain is accept all.\n";

                    foreach ($emails as $email)
                        $results[$email] = self::RESULT_ACCEPT_ALL;

                    // continue;
                }

                if ($this->slow)
                    $this->closeSocket($connect); // use multiple connections
            }

            if ($this->slow) {
                // Check each email with a different connection, pausing between
                foreach ($emails as $email) {
                    if (!$connect) {
                        usleep($this->slowDelay * 1000000); // convert to microseconds

                        // Make a new connection
                        $host = $this->resolvedDomains[$domain];
                        $connect = @fsockopen($host, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);
                    }

                    $this->checkMailboxes($connect, array($email), $results, $host, $domain);
                    $this->closeSocket($connect);
                }
            }
            else {
                $this->checkMailboxes($connect, $emails, $results, $host, $domain);
                $this->closeSocket($connect);
            }
        }

        return $results;
    }

    /**
     * Verify a single email address.
     * @param  string $email The email address.
     * @return string        The verification result, one of the EmailVerifier::RESULT_* constants.
     */
    public function verifySingle($email) {
        $result = $this->verify(array( $email ));
        return $result[$email];
    }


    /**
     * Get the MX record hosts for a domain.
     * @param  string   $domain The domain.
     * @return string[]         The hosts.
     */
    private function getHosts($domain) {
        $mxHosts = array();

        // Get the MX records if the domain is not an IP
        if (!filter_var($domain, FILTER_VALIDATE_IP)) {
            $mxRecordHosts   = array();
            $mxRecordWeights = array();
            getmxrr($domain, $mxRecordHosts, $mxRecordWeights);

            if (!empty($mxRecordHosts)) {
                // Sort the hosts by weight
                $sortedHosts = array();
                for ($i = 0; $i < count($mxRecordHosts); $i++) {
                    $sortedHosts[$mxRecordWeights[$i]] = $mxRecordHosts[$i];
                }
                ksort($sortedHosts, SORT_NUMERIC);
                $sortedHosts[$domain] = 0; // see http://php.net/manual/en/function.getmxrr.php

                $mxHosts = array_values($sortedHosts);
            }
        }

        // Lookup the DNS address record if the MX records failed
        if (empty($mxHosts)) {
            if (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $record_a = dns_get_record($domain, DNS_A);
            }
            else if (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $record_a = dns_get_record($domain, DNS_AAAA);
            }

            if (!empty($record_a)) {
                $mxHosts[] = $record_a[0]['ip'];
            }
        }

        return $mxHosts;
    }

    /**
     * Check if an array of mailboxes are valid.
     * @param resource $sock    The socket connection to the host.
     * @param string[] $emails  The array of email addresses to check.
     * @param array    $results A reference to the array into which the results should be saved as email => result.
     * @param string   $host    The host (for debugging).
     * @param string   $domain  The domain (for debugging).
     */
    private function checkMailboxes($sock, $emails, &$results, $host, $domain) {
        $myHostName = gethostname(); // $_SERVER['SERVER_NAME']

        $out = fread($sock, 1024);
        if ($this->debug)
            echo "Connected to $host ($domain)\n>> $out\n";

        if (preg_match("/^220/i", $out)) {
            fputs($sock, "HELO $myHostName\r\n");
            $out = fread($sock, 1024);

            if ($this->debug)
                echo "<< HELO $myHostName\n>> $out\n";

            fputs($sock, "MAIL FROM: <{$this->fromAddress}>\r\n");
            $from = fread($sock, 1024);

            if ($this->debug)
                echo "<< MAIL FROM: <{$this->fromAddress}>\n>> $from\n";

            foreach ($emails as $email) {
                fputs($sock, "RCPT TO: <$email>\r\n");
                $to = fread($sock, 1024);

                if ($this->debug)
                    echo "<< RCPT TO: <$email>\n>> $to\n";

                if (preg_match("/^250/i", $to)) {
                    if ($results[$email] !== self::RESULT_ACCEPT_ALL)
                        $results[$email] = self::RESULT_VALID;
                }
                else
                    $results[$email] = self::RESULT_INVALID;

                // TODO: other also handles 451/452 to be OK - mailbox full, etc?
            }
        }
        else {
            if ($this->debug)
                echo "$domain SMTP not ready.\n";

            foreach ($emails as $email)
                $results[$email] = self::RESULT_SMTP_FAIL;
        }
    }

    private function closeSocket(&$sock) {
        //fputs($sock, "RSET\r\n");
        fputs($sock, "QUIT");

        if ($this->debug)
            echo "<< QUIT\n";

        fclose($sock);
        $sock = null;
    }

    private static function loadFile($filename) {
        $domains = file($filename);
        $domains = array_map('trim', $domains);
        $domains = array_filter($domains);
        $domains = array_map('strtolower', $domains);
        return $domains;
    }

    private static function getRandomString($length = 10) {
        $chars = 'abcdefghijklmnopqrstuvwxyz';
        $len   = strlen($chars);

        $str = '';
        for ($i = 0; $i < $length; ++$i) {
            $index = ord(openssl_random_pseudo_bytes(1)) % $len;
            $str .= $chars[$index];
        }
        return $str;
    }
}
