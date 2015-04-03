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
    private $debug          = false;

    private $acceptAllPrefix;
    private $disposableDomains = null;
    private $resolvedDomains = array();

    public function __construct() {
        $this->acceptAllPrefix = self::getRandomString();
    }

    public function setChecks($flags) {
        $this->checks = $flags;
    }

    public function getSteps() {
        return $this->checks;
    }

    public function setFromAddress($address) {
        $this->fromAddress = $address;
    }

    public function getFromAddress() {
        return $this->fromAddress;
    }

    public function setConnectTimeout($timeout) {
        $this->connectTimeout = $timeout;
    }

    public function getConnectTimeout() {
        return $this->connectTimeout;
    }

    public function setSlow($on) {
        $this->slow = $on;
    }

    public function getSlow() {
        return $this->slow;
    }

    public function setDebug($on) {
        $this->debug = $on;
    }

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

                    //$this->closeSocket($connect);
                    //continue;
                }

                if ($this->slow)
                    $this->closeSocket($connect); // use multiple connections
            }

            if ($this->slow) {
                // Check each email with a different connection, pausing between
                foreach ($emails as $email) {
                    if (!$connect) {
                        usleep(1000000); // 1 sec

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

    private function checkMailboxes($sock, $emails, &$results, $host, $domain) {
        $myHostName = gethostname(); // $_SERVER['SERVER_NAME']

        $out = fread($sock, 1024);
        if ($this->debug)
            echo "Connected to $host ($domain)\n<< $out\n";

        if (preg_match("/^220/i", $out)) {
            fputs($sock, "HELO $myHostName\r\n");
            $out = fread($sock, 1024);

            if ($this->debug)
                echo ">> HELO $myHostName\n<< $out\n";

            fputs($sock, "MAIL FROM: <{$this->fromAddress}>\r\n");
            $from = fread($sock, 1024);

            if ($this->debug)
                echo ">> MAIL FROM: <{$this->fromAddress}>\n<< $from\n";

            foreach ($emails as $email) {
                fputs($sock, "RCPT TO: <$email>\r\n");
                $to = fread($sock, 1024);

                if ($this->debug)
                    echo ">> RCPT TO: <$email>\n<< $to\n";

                //$results[$email] = preg_match("/^250/i", $to)
                //  ? self::RESULT_VALID
                //  : self::RESULT_INVALID;
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

    //private function checkMailbox($sock, $email) {
    //  fputs($sock, "RCPT TO: <$email>\r\n");
    //  $to = fread($sock, 1024);
    //
    //  if ($this->debug)
    //    echo ">> RCPT TO: <$email>\n<< $to\n";
    //
    //  return preg_match("/^250/i", $to);
    //  // TODO: other also handles 451/452 to be OK - mailbox full, etc?
    //}

    private function closeSocket(&$sock) {
        //fputs($sock, "RSET\r\n");
        fputs($sock, "QUIT");

        if ($this->debug)
            echo ">> QUIT\n";

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

    private static function getRandomString() {
        static $chars = 'abcdefghijklmnopqrstuvwxyz';
        static $len = 26; // strlen($chars)

        $str = '';
        for ($i = 0; $i < 10; ++$i) {
            $index = ord(openssl_random_pseudo_bytes(1)) % $len;
            $str .= $chars[$index];
        }
        return $str;
    }
}
