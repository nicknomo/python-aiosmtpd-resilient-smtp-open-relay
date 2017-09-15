# python-aiosmtpd-resilient-smtp-open-relay
A resilient open relay based on aiosmtpd, that attempts to deliver mail through backup ipv4 and ipv6 gateways.  Multiple DNS servers are also used to provide resiliency

This project will make a resilient SMTP relay using aiosmtpd and smtplib. It is for the Windows platform only.

##settings.ini

#dnsproviderlist 
A list of DNS servers, separated by commas, that will be use to resolve MX records. Your computers default DNS server will be attempted first.

#HELOname
The name that will be announced when a connection is made to an external email server.

#smtprelayport
The port that this email server will bind to

#bindip
The IP address that this email server will bind to

#backupgwip 
The alternate route to try and send email through

#retrycount 
The number of retries to send an outgoing email

#retrydelay
The delay between retries (in seconds).

#ipv6enabled
Enable use of ipv6

#backupgwipv6
IPv6 backup gateway.

#ipv6intnum
The interface to use for ipv6 connections (run "netsh interface ipv6 show interfaces ")
