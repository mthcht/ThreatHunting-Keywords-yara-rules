rule pwnlook
{
    meta:
        description = "Detection patterns for the tool 'pwnlook' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnlook"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string1 = /\\"\!\!Something\swent\swrong\.\sMaybe\sOutlook\sis\snot\srunning\.\\"/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string2 = /\/pwnlook\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string3 = /\/pwnlook\.git/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string4 = "/pwnlook/releases/download/" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string5 = /\/pwnlook35\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string6 = /\/pwnlook481\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string7 = /\\pwnlook\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string8 = /\\pwnlook35\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string9 = /\\pwnlook481\.exe/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string10 = ">pwnlook35<" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string11 = "09aa42564f461b40c5d610872ad6939f8dc31f9bc88be7b9604845fb61be5176" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string12 = "09aa42564f461b40c5d610872ad6939f8dc31f9bc88be7b9604845fb61be5176" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string13 = "1642e74e1c5dfd2863c2100b241e1f4897180a5aba2dd7313060c7953b24f105" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string14 = "2709ef4de6f00a57c05cf4a39228cf87fa522abe20318aa4a09b34ba6cf7eea2" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string15 = "58f9c5248fa5a9cc64622cc12e3963690eed691cd16cbdf5506d5328cfb41f69" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string16 = "5a7f1bf78dd911a486125a32312c46ddcf8ea6523498a49c7cbba44c25097028" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string17 = "67aa975f27ff2c5b874c62c9665c345e54c9dedecacf8b8439d6e30b86906350" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string18 = "6D663511-76E4-4D74-9B3E-191E1471C4EF" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string19 = "9e6659ea06490dde8a0815c3df51dfa242e6f9f0dd8f5a3ba3e7e4cdc2e77630" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string20 = "amjcyber/pwnlook" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string21 = "d3423d953de70480415b1bb516c2a5c635cf2c78a531cc5e4afce3ab11725e90" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string22 = "e8a017f717909f20e325d901af37d25b1e19e363923dfe61dfecae77d7d979ef" nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string23 = /pwnlook\.exe\s/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string24 = /pwnlook35\.exe\s/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string25 = /pwnlook481\.exe\s/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string26 = /regsvr32\.exe\s\.\\Redemption\.dll/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string27 = /regsvr32\.exe\s\.\\Redemption64\.dll/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string28 = /regsvr32\.exe\s\-u\s\.\\Redemption\.dll/ nocase ascii wide
        // Description: An offensive postexploitation tool that will give you complete control over the Outlook desktop application and therefore to the emails configured in it
        // Reference: https://github.com/amjcyber/pwnlook
        $string29 = /regsvr32\.exe\s\-u\s\.\\Redemption64\.dll/ nocase ascii wide
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
