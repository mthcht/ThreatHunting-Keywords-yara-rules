rule power_pwn
{
    meta:
        description = "Detection patterns for the tool 'power-pwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "power-pwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string1 = /\/power\-pwn\.git/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string2 = /\\malware_runner\.py/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string3 = /\\power\-pwn\\/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string4 = /Cleanup\-57BFF48E\-24FB\-48E9\-A390\-AC62ADF38B07\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string5 = /CodeExec\-D37DA402\-3829\-492F\-90D0\-8EC3909514EB\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string6 = /Endpoint\-EE15B860\-9EEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string7 = /Exfil\-EC266392\-D6BC\-4F7B\-A4D1\-410166D30B55\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string8 = "mbrg/power-pwn" nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string9 = /powerpwn\.powerdump/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string10 = "powerpwn_tests" nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string11 = "power-pwn-main" nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string12 = /Ransomware\-E20F7CED\-42AD\-485E\-BE4D\-DE21DCE58EC0\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string13 = /RunCleanup\-77740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string14 = /RunCodeExec\-75740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string15 = /RunExfil\-78740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string16 = /RunRansomware\-76740706\-9DEC\-EC11\-BB3D\-0022482CA4A7\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string17 = /RunStealCookie\-8B5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string18 = /RunStealPowerAutomateToken\-8C5C57DA\-F404\-ED11\-82E4\-0022481BF843\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string19 = /StealCookie\-28050355\-D9DF\-4CE7\-BFBC\-4F7DDE890C2A\.json/ nocase ascii wide
        // Description: An offensive and defensive security toolset for Microsoft 365 Power Platform
        // Reference: https://github.com/mbrg/power-pwn
        $string20 = /StealPowerAutomateToken\-C4E7B7DA\-54E4\-49AB\-B634\-FCCD77C65025\.json/ nocase ascii wide
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
