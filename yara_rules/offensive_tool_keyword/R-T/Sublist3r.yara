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
        $string1 = "/Sublist3r" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string2 = "1c5610c15476512d11f83809cd70dd22ffe4a9042aa11ab251d8ecf8f3772bcb" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string3 = "321266cbbd238c3172a32249b3cfb9101d0b29a15c0418e62290d9dc3aace58f" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string4 = "75e28e8d08eada3a62ea3decfc6ce51717ef7b8ef581693d7d57111c514f00da" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string5 = "77f72dddfd3e604f689b437c0e813ad2935b0ca7eb93b6b46e344b97105ecf05" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string6 = "98b1b6fb910bda21e3e331382c73dd81f5bd9f36165b1719f446ea9e253f0f16" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string7 = "d99f3036f858ed7c0ff1da150b7bcc8a41b0fd422e36f9d6843091221ea5be01" nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string8 = /https\:\/\/api\.sublist3r\.com\/search\.php\?domain\=/ nocase ascii wide
        // Description: Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google. Yahoo. Bing. Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft. Virustotal. ThreatCrowd. DNSdumpster and ReverseDNS. subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.
        // Reference: https://github.com/aboul3la/Sublist3r
        $string9 = /sublist3r\.py/ nocase ascii wide

    condition:
        any of them
}
