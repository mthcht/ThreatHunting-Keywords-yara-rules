rule poc
{
    meta:
        description = "Detection patterns for the tool 'poc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string1 = /\sRCE\.py\s\-/ nocase ascii wide
        // Description: Exploit for the CVE-2023-23399
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string2 = /\/CVE\-.{0,100}_EXPLOIT_0DAY\// nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string3 = "/Hashi0x/" nocase ascii wide
        // Description: Simple PoC in PowerShell for CVE-2023-23397
        // Reference: https://github.com/ka7ana/CVE-2023-23397
        $string4 = /\/ka7ana\/CVE.{0,100}\.ps1/ nocase ascii wide
        // Description: Exploit for the CVE-2023-23397
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string5 = "/MsgKitTestTool/" nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string6 = "/PoC-CVE-2023-21554" nocase ascii wide
        // Description: Exploit for the CVE-2023-23398
        // Reference: https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY
        $string7 = "/sqrtZeroKnowledge/CVE-" nocase ascii wide
        // Description: Simple and dirty PoC of the CVE-2023-23397 vulnerability impacting the Outlook thick client.
        // Reference: https://github.com/Trackflaw/CVE-2023-23397
        $string8 = /\/Trackflaw\/CVE.{0,100}\.py/ nocase ascii wide
        // Description: Windows Message Queuing vulnerability exploitation with custom payloads
        // Reference: https://github.com/Hashi0x/PoC-CVE-2023-21554
        $string9 = /cve\-2023\-21554\.nse/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
