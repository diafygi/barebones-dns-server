import re

def special_function123(question):
    """
    Process a DNS question and return a query type reference as the result.

    DNS question format: {
        "name": b"www.example.com", # domain being queried
        "type": "A",                # query type (e.g. CNAME, A, TXT, etc.)
        "class": "IN",              # query class (always "IN" for internet)
    }
    """
    return  {
        "A": [
            ["192.168.1.0", 60],
        ],
        "TXT": [
            ["This is a dynamic TXT entry for {}".format(question['name'].decode()).encode(), 60],
        ],
        "MX": [
            [{"preference": 10, "exchange": b"special123-mx.example.com"}, 60],
        ],
    }

DNS_CONFIG = {

    # which base domains this server manages
    "authoritative_domains": [
        b"example.com",
    ],

    # will stop at the first matched domain
    "domains": [

        # specific domain example
        [
            re.compile(b"^www\.example\.com$"),
            {
                "A": [
                    ["192.168.1.1", 60],
                ],
                "TXT": [
                    [b"This is a txt entry for www", 60],
                ],
                "MX": [
                    [{"preference": 10, "exchange": b"www-mx.example.com"}, 60],
                ],
            },
        ],

        # you can use python logic for dynamic processing, too
        [
            re.compile(b"^special\.example\.com$"),
            special_function123,  # must return same dict format as static config for domains
                                  # (e.g. {"A": [["192.168.1.1", 60], ...], ...})
        ],

        # wildcard examples
        [
            re.compile(b"^[^\.]+\.www\.example\.com$"),
            {
                "A": [
                    ["192.168.1.99", 60],
                    ["192.168.1.100", 60],
                ],
                "TXT": [
                    [b"This is a txt entry for wildcard *.www", 60],
                ],
                "MX": [
                    [{"preference": 10, "exchange": b"wildcard-mx.example.com"}, 60],
                ],
            },
        ],
        [
            re.compile(b"^[^\.]+\.special\.example\.com$"),
            special_function123,
        ],
    ],
}

