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
        $string1 = /.{0,1000}\/DNSExfiltrator.{0,1000}/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string2 = /.{0,1000}dnsexfiltrator\..{0,1000}/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string3 = /.{0,1000}DNSExfiltratorLib.{0,1000}/ nocase ascii wide
        // Description: DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
        // Reference: https://github.com/Arno0x/DNSExfiltrator
        $string4 = /.{0,1000}Invoke\-DNSExfiltrator.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
