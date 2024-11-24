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
        $string4 = " --fakedomains " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string5 = " --fakeip " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string6 = " --fakeipv6 " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string7 = " --fakemail " nocase ascii wide
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
        $string13 = "/dnschef-ng/" nocase ascii wide
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
        $string19 = "byt3bl33d3r/dnschef-ng" nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string20 = /byt3bl33d3r\@pm\.me/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string21 = /cooking\sA\sreplies\sto\spoint\sto\s.{0,100}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string22 = /cooking\sAAAA\sreplies\sto\spoint\sto\s.{0,100}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string23 = "cooking all A replies to point to " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string24 = "cooking all AAAA replies to point to " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string25 = "cooking all CNAME replies to point to " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string26 = "cooking all MX replies to point to " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string27 = "cooking all NS replies to point to " nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string28 = /cooking\sCNAME\sreplies\sto\spoint\sto\s.{0,100}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string29 = /cooking\sMX\sreplies\sto\spoint\sto\s.{0,100}\smatching\:\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string30 = /cooking\sNS\sreplies\sto\spoint\sto\s.{0,100}\smatching\:\s/ nocase ascii wide
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
        $string35 = "dnschef-ng-main" nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string36 = /\-\-file\sdnschef\.ini\s/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string37 = "pip install dnschef" nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string38 = /shit\.fuck\.org/ nocase ascii wide
        // Description: DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example - a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.
        // Reference: https://github.com/byt3bl33d3r/dnschef-ng
        $string39 = /something\.wattahog\.org/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
