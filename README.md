# Python barebones DNS server

This is a barebones DNS server implementation in Python that can generate dynamic responses.

I wrote this to learn the DNS protocol and be able dynamically respond DNS queries.

## Config format

Config is a python dict with `authoritative_domains` and `domains` lists in it. For the command line interface, you can specify a python module that has a `DNS_CONFIG` variable in it. See `example_config.py` for a more expansive example config.

Format:
```
DNS_CONFIG = {
    "authoritative_domains": [
        b"<base_domain>",
        ...
    ],
    "domains": [

        # can be a fixed set of records
        [<compiled_regex_for_domain>, {"<record_type>": [<record_data>, <record_ttl>], ...}],

        # or a python function that returns a set of records
        [<compiled_regex_for_domain>, <python_function>],

        ...
    ],
}
```

Example:
```
DNS_CONFIG = {
    "authoritative_domains": [
        b"example.com",
    ],
    "domains": [
        [re.compile(b"^example\.com$"), {"A": [["192.168.1.1", 60]]}],
        [re.compile(b"^www\.example\.com$"), {"A": [["192.168.1.1", 60]]}],
    ],
}
```


### Record data formats

The `<record_data>` format in configs depends on the type of record being requested (e.g. CNAME, A, TXT, etc.).

* `A` - String IPv4 address (example: `"192.168.1.1"`)
* `AAAA` - String IPv6 address (example: `"14321:0:1:2:3:4:567:89ab"`)
* `CNAME` - Byte-string domain name (example: `b"www.example.com"`)
* `NS` - Byte-string domain name (example: `b"www.example.com"`)
* `PTR` - Byte-string domain name (example: `b"www.example.com"`)
* `TXT` - Byte-string (example: `b"example string here"`)
* `MX` - Dictonary with `preference` int and `exchange` domain (example: `{"preference": 10, "exchange": b"mx.example.com"}`)


## Example: Run a DNS server using the example config

Run the server using the default config (uses `example_config.py`):
```
$ python3 -m barebones_dns_server
Running DNS server on 127.0.0.1:5353...
```

In another terminal, make a DNS query:
```
$ dig @127.0.0.1 -p 5353 A www.example.com

; <<>> DiG 9.18.18-0ubuntu0.22.04.2-Ubuntu <<>> @127.0.0.1 -p 5353 A www.example.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29647
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.example.com.		IN	A

;; ANSWER SECTION:
www.example.com.	60	IN	A	192.168.1.1

;; Query time: 15 msec
;; SERVER: 127.0.0.1#5353(127.0.0.1) (UDP)
;; WHEN: Sat May 11 13:17:53 CDT 2024
;; MSG SIZE  rcvd: 64
```


## Example: Run your own custom UDP server

```
import re
import socketserver
import barebones_dns_server

class MyDNSHandler(barebones_dns_server.BarebonesDNSUDPHandler):
    DNS_CONFIG = {
        "authoritative_domains": [b"example.com"],
        "domains": [
            [
                re.compile(b"^www\.example\.com$"),
                {"A": [["192.168.1.1", 60]]},
            ],
        ],
    }

if __name__ == "__main__":
    socketserver.ForkingUDPServer.allow_reuse_address = True
    with socketserver.ForkingUDPServer(("127.0.0.1", 5353), MyDNSHandler) as server:
        server.serve_forever()
```


## License

Released under the MIT license

