rule SpaceRunner
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string1 = /\s\-f\sFind\-AllVulns/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string2 = /\s\-f\sFind\-PathDLLHijack/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string3 = /\s\-f\sGet\-DomainGroupMember.{0,100}\s\-a\s.{0,100}\-Identity\s.{0,100}admin.{0,100}\s\-Recurse/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string4 = /\s\-f\sInvoke\-Inveigh/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string5 = /\/out\:spacerunner\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string6 = /\/SpaceRunner\.git/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string7 = /\/target\:exe\sspacerunner\.cs/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string8 = /\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string9 = /\\inveigh\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string10 = /\\Powerup\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string11 = /\\Powerview\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string12 = /\\sherlock\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string13 = /beacon\.ps1.{0,100}beacon\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string14 = /Mr\-B0b\/SpaceRunner/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string15 = /spacerunner\.exe\s\-i\s.{0,100}\.ps1.{0,100}\s\-o\s.{0,100}\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string16 = /SpaceRunner\-master\.zip/ nocase ascii wide
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
