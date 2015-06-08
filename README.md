# EmailVerifier

A PHP class that can be used to verify email addresses.

This fork adds some additional features and incorporates the verification into a class so some information can be reused between calls.

In addition to making sure the mailbox exists, these checks are available:

- Check the syntax of the email.
- Check whether the domain is on a list of disposable domains.
- Check whether the mail server reports all mailboxes as valid.

The possible results are:

- bad syntax
- disposable
- no mx records
- invalid domain
- smtp fail
- accept all
- invalid
- valid :thumbsup:

## Usage

```php
$v = new EmailVerifier();
$v->setDebug(true);

$results = $v->verify(array(
  'email@gmail.com',
  'support@github.com',
  'email@example.com',
));

echo "\n";
foreach ($results as $email => $result) {
  echo "$email: $result\n";
}
```

Example output:

```
Connected to gmail-smtp-in.l.google.com (gmail.com)
>> 220 mx.google.com ESMTP abc.123 - gsmtp

<< HELO [your-server]
>> 250 mx.google.com at your service

<< MAIL FROM: <test@example.com>
>> 250 2.1.0 OK abc.123 - gsmtp

<< RCPT TO: <mmiviadjpp@gmail.com>
>> 550-5.1.1 The email account that you tried to reach does not exist. Please try
550-5.1.1 double-checking the recipient's email address for typos or
550-5.1.1 unnecessary spaces. Learn more at
550 5.1.1 https://support.google.com/mail/answer/6596 abc.123 - gsmtp

<< QUIT
Connected to gmail-smtp-in.l.google.com (gmail.com)
>> 220 mx.google.com ESMTP def.456 - gsmtp

<< HELO [your-server]
>> 250 mx.google.com at your service

<< MAIL FROM: <test@example.com>
>> 250 2.1.0 OK def.456 - gsmtp

<< RCPT TO: <email@gmail.com>
>> 550 5.2.1 The email account that you tried to reach is disabled. def.456 - gsmtp

<< QUIT
Connected to ASPMX.L.GOOGLE.com (github.com)
>> 220 mx.google.com ESMTP ghi.789 - gsmtp

<< HELO [your-server]
>> 250 mx.google.com at your service

<< MAIL FROM: <test@example.com>
>> 250 2.1.0 OK ghi.789 - gsmtp

<< RCPT TO: <mmiviadjpp@github.com>
>> 550-5.1.1 The email account that you tried to reach does not exist. Please try
550-5.1.1 double-checking the recipient's email address for typos or
550-5.1.1 unnecessary spaces. Learn more at
550 5.1.1 https://support.google.com/mail/answer/6596 ghi.789 - gsmtp

<< QUIT
Connected to ASPMX.L.GOOGLE.com (github.com)
>> 220 mx.google.com ESMTP jkl.012 - gsmtp

<< HELO [your-server]
>> 250 mx.google.com at your service

<< MAIL FROM: <test@example.com>
>> 250 2.1.0 OK jkl.012 - gsmtp

<< RCPT TO: <support@github.com>
>> 250 2.1.5 OK jkl.012 - gsmtp

<< QUIT
example.com is disposable.

email@gmail.com: invalid
support@github.com: valid
email@example.com: disposable
```

See [verify.php](verify.php) for all the possible options.

## Notes

- Some mail servers will silently reject the test message to prevent spammers from checking against their users' emails and filter the valid emails, so this function might not work properly with all mail servers.
