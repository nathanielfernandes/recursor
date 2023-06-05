# recursor
## A WIP tiny dns server

This is a research project to learn more about dns and how it works. it is not intended to be used.

**TODO:**
- Caching
- DNSSEC
- EDNS

### Example use
```
dig @127.0.0.1 -p 2053 nathanielfernandes.ca

; <<>> DiG 9.16.1-Ubuntu <<>> @127.0.0.1 -p 2053 nathanielfernandes.ca
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 30913
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;nathanielfernandes.ca.		IN	A

;; Query time: 80 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Mon Jun 05 01:15:11 EDT 2023
;; MSG SIZE  rcvd: 39
```
server output:
```
Received query for google.com A
Looking up google.com A from 198.41.0.4
Looking up google.com A from 192.5.6.30
Looking up google.com A from 216.239.34.10
Received query for google.com A
Looking up google.com A from 198.41.0.4
Looking up google.com A from 192.5.6.30
Looking up google.com A from 216.239.34.10
Received query for nathanielfernandes.ca A
Looking up nathanielfernandes.ca A from 198.41.0.4
Looking up nathanielfernandes.ca A from 185.159.196.2
Looking up nia.ns.cloudflare.com A from 185.159.196.2
```
### Resources 
- [DNS GUIDE](https://github.com/EmilHernvall/dnsguide)
- [tcipguide](http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm)
- [DNS RFC](https://tools.ietf.org/html/rfc1035)


