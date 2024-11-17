rule dir
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: threat actors searched for Active Directory related DLLs in directories
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1 = /\sdir\s\/s\s.{0,100}\/\sMicrosoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
        // Description: lists files and directories in the c:\windows\kb directory related to updates or system configurations
        // Reference: N/A
        $string2 = /dir\s\/a\s\/b\sc\:\\windows\\kb/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string3 = /dir\s\/a\:h\sC\:\\Users\\.{0,100}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string4 = /dir\s\/a\:h\sC\:\\Users\\.{0,100}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: List Users with dir
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string5 = /dir\s\/b\s\/ad\s\\"C\:\\Users\\"/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string6 = /dir\s\/b\/a\s\%appdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string7 = /dir\s\/b\/a\s\%localappdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: Find the IDs of protected secrets for a specific user
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string8 = /dir\sC\:\\Users\\.{0,100}\\AppData\\Local\\Microsoft\\Credentials/ nocase ascii wide
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
