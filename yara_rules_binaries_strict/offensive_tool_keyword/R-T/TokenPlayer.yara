rule TokenPlayer
{
    meta:
        description = "Detection patterns for the tool 'TokenPlayer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenPlayer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string1 = /\s\-\-maketoken\s\-\-username\s.{0,100}\s\-\-password\s.{0,100}\s\-\-domain\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string2 = /\s\-\-spoofppid\s\-\-ppid\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string3 = /\sUAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string4 = /\.exe\s\-\-exec\s\-\-pid\s.{0,100}\s\-\-prog\s.{0,100}cmd\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string5 = /\.exe\s\-\-impersonate\s\-\-pid\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string6 = /\/TokenPlayer\.git/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string7 = /\/UAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string8 = /\[\+\]ImpersonateLoggedOnUser\(\)\ssucceed\!/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string9 = /\\ProcessSpoofing\.h/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string10 = /\\TokenPlayer\.cpp/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string11 = /\\TokenPlayer\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string12 = /\\TokenPlayer\\TokenPlayer\\/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string13 = /\\UAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string14 = /\]Spawning\sProcess\swith\sSpoofed\sParent/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string15 = /0ADFD1F0\-7C15\-4A22\-87B4\-F67E046ECD96/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string16 = /95d19ae58bbd6b38b4988fae5c7b514c8451a15e940f1392bcf1f93374364054/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string17 = /S1ckB0y1337\/TokenPlayer/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string18 = /TokenPlayer\-v0\.3\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string19 = /TokenPlayer\-v0\.4\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string20 = /TokenPlayer\-v0\.5\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string21 = /TokenPlayer\-v0\.6\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string22 = /TokenPlayer\-v0\.7\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string23 = /TokenPlayer\-v0\.8\.exe/ nocase ascii wide
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
