<?php

class EmailVerifier {
    const CHECK_SYNTAX     = 0x01;
    const CHECK_DISPOSABLE = 0x02;
    //const CHECK_DNS        = 0x04;
    //const CHECK_SMTP       = 0x08;
    //const CHECK_MAILBOX    = 0x10;
    const CHECK_ACCEPT_ALL = 0x20;
    const CHECK_EVERYTHING = 0x3F;

    const RESULT_BAD_SYNTAX     = 'syntax';
    const RESULT_DISPOSABLE     = 'disposable';
    const RESULT_INVALID_DOMAIN = 'invalid_domain';
    const RESULT_NO_MX_RECORD   = 'invalid_mx_record';
    const RESULT_ACCEPT_ALL     = 'accept_all';
    const RESULT_INVALID        = 'invalid';
    const RESULT_VALID          = 'valid';

    private $checks = self::CHECK_EVERYTHING;
    private $fromAddress = 'test@example.com';
    private $connectTimeout = 60;
    private $debug = false;

    private $acceptAllPrefix;
    private $disposableDomains = null;


    public function __construct($options = array()) {
        if (isset($options['flags']))
            $this->setChecks($options['checks']);

        if (isset($options['from']))
            $this->setFromAddress($options['from']);

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

        $myHostName = gethostname(); // $_SERVER['SERVER_NAME']

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

            $mxHosts   = array();
            $mxWeights = array();

            // Get the MX records if the domain is not an IP
            if (!filter_var($domain, FILTER_VALIDATE_IP)) {
                getmxrr($domain, $mxHosts, $mxWeights);
            }

            if (!empty($mxHosts)) {
                // Sort the hosts by weight
                $sortedHosts = array();
                for ($i = 0; $i < count($mxHosts); $i++) {
                    $sortedHosts[$mxWeights[$i]] = $mxHosts[$i];
                }
                ksort($sortedHosts, SORT_NUMERIC);
                $sortedHosts[$domain] = 0; // see http://php.net/manual/en/function.getmxrr.php

                // Try connecting to each host in order, and use the first host which succeeds
                foreach ($sortedHosts as $host) {
                    $connect = @fsockopen($host, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);

                    if ($connect) {
                        break;
                    }
                    else if ($this->debug) {
                        echo "Could not connect to $host ($domain): $connectErrStr ($connectErrNo)\n";
                    }
                }
            }
            else {
                // Get the DNS address record
                if (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $record_a = dns_get_record($domain, DNS_A);
                }
                else if (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $record_a = dns_get_record($domain, DNS_AAAA);
                }

                // Try connecting to the record
                if (!empty($record_a)) {
                    $host = $record_a[0]['ip'];
                    $connect = @fsockopen($host, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);

                    if (!$connect && $this->debug) {
                        echo "Could not connect to $host ($domain): $connectErrStr ($connectErrNo)\n";
                    }
                }
                else {
                    if ($this->debug)
                        echo "No MX records for $domain.\n";

                    foreach ($emails as $email)
                        $results[$email] = self::RESULT_NO_MX_RECORD;
                    continue;
                }
            }

            //$connect = @fsockopen($mx_ip, 25, $connectErrNo, $connectErrStr, $this->connectTimeout);
            if (isset($connect) && $connect) {
                $out = fread($connect, 1024);
                if ($this->debug)
                    echo "Connected to $host ($domain)\n<< $out\n";

                if (preg_match("/^220/i", $out)) {
                    fputs($connect, "HELO $myHostName\r\n");
                    $out = fread($connect, 1024);

                    if ($this->debug)
                        echo ">> HELO $myHostName\n<< $out\n";

                    fputs($connect, "MAIL FROM: <{$this->fromAddress}>\r\n");
                    $from = fread($connect, 1024);

                    if ($this->debug)
                        echo ">> MAIL FROM: <{$this->fromAddress}>\n<< $from\n";

                    if ($this->checks & self::CHECK_ACCEPT_ALL) {
                        // Check if a random mailbox is available
                        if ($this->checkMailbox($connect, $this->acceptAllPrefix . '@' . $domain)) {
                            if ($this->debug)
                                echo "$domain is accept all.\n";

                            foreach ($emails as $email)
                                $results[$email] = self::RESULT_ACCEPT_ALL;

                            $this->closeSocket($connect);
                            continue;
                        }
                    }

                    foreach ($emails as $email) {
                        $results[$email] = $this->checkMailbox($connect, $email)
                            ? self::RESULT_VALID
                            : self::RESULT_INVALID;
                    }

                    $this->closeSocket($connect);
                }
                else {
                    echo "Was not expecting this!!\n";
                }
            }
            else {
                foreach ($emails as $email)
                    $results[$email] = self::RESULT_INVALID_DOMAIN;
            }
        }

        return $results;
    }

    public function verifySingle($email) {
        $result = $this->verify(array( $email ));
        return $result[$email];
    }


    private function checkMailbox($sock, $email) {
        fputs($sock, "RCPT TO: <$email>\r\n");
        $to = fread($sock, 1024);

        if ($this->debug)
            echo ">> RCPT TO: <$email>\n<< $to\n";

        return preg_match("/^250/i", $to);
        // TODO: other also handles 451/452 to be OK - mailbox full, etc?
    }

    private function closeSocket($sock) {
        //fputs($sock, "RSET");
        fputs($sock, "QUIT");

        if ($this->debug)
            echo ">> RSET\n>> QUIT\n";

        fclose($sock);
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
            // Find a secure random number within the range needed
            $index = ord(openssl_random_pseudo_bytes(1)) % $len;

            // Each iteration, pick a random character from the allowable string and append it to the password
            $str .= $chars[$index];
        }

        return $str;
    }
}
