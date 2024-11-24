rule AutoSUID
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string1 = /\sAutoSUID\.sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string2 = /\spwn_php\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string3 = /\spwn_python\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string4 = /\.\/AutoSUID\.sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string5 = /\/AutoSUID\.git/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string6 = /\/pwn_php\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string7 = /\/pwn_python\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string8 = /AutoSUID\-main\./ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string9 = "aW1wb3J0IG9zOyBvcy5leGVjbCgiL2Jpbi9zaCIsICJzaCIsICItcCIp" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string10 = "IvanGlinkin/AutoSUID" nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string11 = "PD9waHAKcGNudGxfZXhlYygnL2Jpbi9zaCcsIFsnLXAnXSk7Cj8" nocase ascii wide
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
