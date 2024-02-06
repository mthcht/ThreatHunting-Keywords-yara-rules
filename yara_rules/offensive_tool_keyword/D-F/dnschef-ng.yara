rule dnschef_ng
{
    meta:
        description = "Detection patterns for the tool 'dnschef-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnschef-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string1 = /\sdnschef\.exe/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string2 = /\sdnschef\.py/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string3 = /\s\-\-fakealias\swww\.fake\.com/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string4 = /\s\-\-fakedomains\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string5 = /\s\-\-fakeip\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string6 = /\s\-\-fakeipv6\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string7 = /\s\-\-fakemail\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string8 = /\/dnschef\.exe/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string9 = /\/dnschef\.ini/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string10 = /\/dnschef\.log/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string11 = /\/dnschef\.py/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string12 = /\/dnschef\-ng\.git/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string13 = /\/dnschef\-ng\// nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string14 = /\\dnschef\.exe/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string15 = /\\dnschef\.ini/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string16 = /\\dnschef\.log/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string17 = /\\dnschef\.py/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string18 = /\\dnschef\-ng\\/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string19 = /byt3bl33d3r\/dnschef\-ng/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string20 = /byt3bl33d3r\@pm\.me/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string21 = /cooking\sA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string22 = /cooking\sAAAA\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string23 = /cooking\sall\sA\sreplies\sto\spoint\sto\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string24 = /cooking\sall\sAAAA\sreplies\sto\spoint\sto\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string25 = /cooking\sall\sCNAME\sreplies\sto\spoint\sto\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string26 = /cooking\sall\sMX\sreplies\sto\spoint\sto\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string27 = /cooking\sall\sNS\sreplies\sto\spoint\sto\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string28 = /cooking\sCNAME\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string29 = /cooking\sMX\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string30 = /cooking\sNS\sreplies\sto\spoint\sto\s.{0,1000}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string31 = /dnschef\.exe\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string32 = /dnschef\.logger/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string33 = /dnschef\.py\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string34 = /dnschef\.utils/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string35 = /dnschef\-ng\-main/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string36 = /\-\-file\sdnschef\.ini\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string37 = /pip\sinstall\sdnschef/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string38 = /shit\.fuck\.org/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string39 = /something\.wattahog\.org/ nocase ascii wide

    condition:
        any of them
}
