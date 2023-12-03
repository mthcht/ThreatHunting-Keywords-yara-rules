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
        $string1 = /.{0,1000}\sdnschef\.exe.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string2 = /.{0,1000}\sdnschef\.py.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string3 = /.{0,1000}\s\-\-fakealias\swww\.fake\.com.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string4 = /.{0,1000}\s\-\-fakedomains\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string5 = /.{0,1000}\s\-\-fakeip\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string6 = /.{0,1000}\s\-\-fakeipv6\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string7 = /.{0,1000}\s\-\-fakemail\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string8 = /.{0,1000}\/dnschef\.exe.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string9 = /.{0,1000}\/dnschef\.ini.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string10 = /.{0,1000}\/dnschef\.log.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string11 = /.{0,1000}\/dnschef\.py.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string12 = /.{0,1000}\/dnschef\-ng\.git.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string13 = /.{0,1000}\/dnschef\-ng\/.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string14 = /.{0,1000}\\dnschef\.exe.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string15 = /.{0,1000}\\dnschef\.ini.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string16 = /.{0,1000}\\dnschef\.log.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string17 = /.{0,1000}\\dnschef\.py.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string18 = /.{0,1000}\\dnschef\-ng\\.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string19 = /.{0,1000}byt3bl33d3r\/dnschef\-ng.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string20 = /.{0,1000}byt3bl33d3r\@pm\.me.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string21 = /.{0,1000}cooking\sA\sreplies\sto\spoint\sto\s.{0,1000}\smatching:\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string22 = /.{0,1000}cooking\sAAAA\sreplies\sto\spoint\sto\s.{0,1000}\smatching:\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string23 = /.{0,1000}cooking\sall\sA\sreplies\sto\spoint\sto\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string24 = /.{0,1000}cooking\sall\sAAAA\sreplies\sto\spoint\sto\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string25 = /.{0,1000}cooking\sall\sCNAME\sreplies\sto\spoint\sto\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string26 = /.{0,1000}cooking\sall\sMX\sreplies\sto\spoint\sto\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string27 = /.{0,1000}cooking\sall\sNS\sreplies\sto\spoint\sto\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string28 = /.{0,1000}cooking\sCNAME\sreplies\sto\spoint\sto\s.{0,1000}\smatching:\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string29 = /.{0,1000}cooking\sMX\sreplies\sto\spoint\sto\s.{0,1000}\smatching:\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string30 = /.{0,1000}cooking\sNS\sreplies\sto\spoint\sto\s.{0,1000}\smatching:\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string31 = /.{0,1000}dnschef\.exe\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string32 = /.{0,1000}dnschef\.logger.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string33 = /.{0,1000}dnschef\.py\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string34 = /.{0,1000}dnschef\.utils.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string35 = /.{0,1000}dnschef\-ng\-main.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string36 = /.{0,1000}\-\-file\sdnschef\.ini\s.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string37 = /.{0,1000}pip\sinstall\sdnschef.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string38 = /.{0,1000}shit\.fuck\.org.{0,1000}/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string39 = /.{0,1000}something\.wattahog\.org.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
