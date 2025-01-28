rule RogueWinRM
{
    meta:
        description = "Detection patterns for the tool 'RogueWinRM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueWinRM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string1 = /\/RogueWinRM\.git/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string2 = /\\RogueWinRM\.sln/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string3 = /\\RogueWinRM\\/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string4 = /\\windows\\temp\\nc64\.exe/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string5 = "antonioCoco/RogueWinRM" nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string6 = "B03A3AF9-9448-43FE-8CEE-5A2C43BFAC86" nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string7 = "ec260817672bcc48f734f89e9eac84ebc7903924b36f807caf58c6820c0e336c" nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string8 = "RogueWinRM " nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string9 = /RogueWinRM\.cpp/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string10 = /RogueWinRM\.exe/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string11 = /RogueWinRM\.zip/ nocase ascii wide
        // Description: RogueWinRM is a local privilege escalation exploit that allows to escalate from a Service account (with SeImpersonatePrivilege) to Local System account if WinRM service is not running
        // Reference: https://github.com/antonioCoco/RogueWinRM
        $string12 = /WinRM\salready\srunning\son\sport\s5985\.\sUnexploitable\!/ nocase ascii wide
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
