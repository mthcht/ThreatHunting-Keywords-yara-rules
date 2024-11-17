rule Psnmap
{
    meta:
        description = "Detection patterns for the tool 'Psnmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Psnmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string1 = /\sPSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string2 = /\/PSnmap\.git/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string3 = /\/PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string4 = /\/PSnmap\.psd1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string5 = /\/PSnmap\.psm1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string6 = /\\PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string7 = /\\PSnmap\.psd1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string8 = /\\PSnmap\.psm1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string9 = /5e60bc27d24e7a5b641fa59ee55002dae44ce9dde494df9783a9aa002455c6d2/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string10 = /Add\-Member\s\-MemberType\sNoteProperty\s\-Name\sPing\s\-Value\s\(Test\-Connection\s\-ComputerName\s.{0,100}\s\-Quiet\s\-Count\s1\)\s\-Force/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string11 = /ba20280d3b1e1ba3539232ee1b32c6071958811da1cb6716aeb33480977da408/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string12 = /be09f42e9225e82fe619a700b93d33e3bf0603266b7865d45a786630d4303aa7/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string13 = /EliteLoser\/PSnmap/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string14 = /Install\-Module\s\-Name\sPSnmap\s\-Scope\s/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string15 = /Invoke\-Psnmap/ nocase ascii wide
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
