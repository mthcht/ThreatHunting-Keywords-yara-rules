rule DNSExfiltrator
{
    meta:
        description = "Detection patterns for the tool 'DNSExfiltrator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSExfiltrator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string1 = /\$DNSExfiltratorLib/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string2 = /\/DNSExfiltrator/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string3 = /\/dnsExfiltrator\.dll/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string4 = /\/DNSExfiltrator\.git/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string5 = /\/dnsexfiltrator\.py/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string6 = /\\dnsExfiltrator\.cs/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string7 = /\\dnsExfiltrator\.dll/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string8 = /\\dnsexfiltrator\.py/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string9 = /5cf800056e1db3399b0f3dd19eed7c0ae2c187816c2a0e0da36191154726fb38/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string10 = /Arno0x\/DNSExfiltrator/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string11 = /cf840440b78deadaf6f4f085db860d3bc69ce480edc505a378f733127ff37bc6/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string12 = /dec6b9f665b6679c1c9bedbd9d51ea9faf76f29619b7cc4892f22b9659719335/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string13 = /dnsExfiltrator\.exe/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string14 = /DNSExfiltratorLib/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string15 = /e3991de30b4675d89877b4b22a36e71c1ac11b399e9b6826195e87354f4d6837/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string16 = /ed937bcd5dc05f1021aa83afdb47af266083ef47228e23a32292bad577c53191/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string17 = /f079fee94bbb57fd41bab9139839f5458137b0a8bcd692642f22f08ce647cae2/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string18 = /Invoke\-DNSExfiltrator/ nocase ascii wide

    condition:
        any of them
}
