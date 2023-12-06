rule Sublist3r
{
    meta:
        description = "Detection patterns for the tool 'Sublist3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sublist3r"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string1 = /Sublist3r/ nocase ascii wide

    condition:
        any of them
}
