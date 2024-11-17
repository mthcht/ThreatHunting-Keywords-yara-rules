rule SharpEdge
{
    meta:
        description = "Detection patterns for the tool 'SharpEdge' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEdge"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string1 = /\/SharpEdge\.exe/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string2 = /\/SharpEdge\.git/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string3 = /\\SharpEdge\.csproj/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string4 = /\\SharpEdge\.exe/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string5 = /\\SharpEdge\.sln/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string6 = /\\SharpEdge\-master/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string7 = /0d21ae4c38549782f8b066155b671b2a356721209a5ecaa64bba6edcc6e2f97e/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string8 = /2388c7f7f1073b922d235f675e32e1b6b8809dcef1cce1113bf712402cbad1cd/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string9 = /75f068e65a36c0dfcd7b59c00ab3a0e73f6bc07ca84091f472caada25e32cfcd/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string10 = /D116BEC7\-8DEF\-4FCE\-BF84\-C8504EF4E481/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string11 = /rvrsh3ll\/SharpEdge/ nocase ascii wide
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
