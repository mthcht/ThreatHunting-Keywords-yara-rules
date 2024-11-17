rule EASSniper
{
    meta:
        description = "Detection patterns for the tool 'EASSniper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EASSniper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string1 = /\sEASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string2 = /\seas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string3 = /\sowa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string4 = /\/EASSniper\.git/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string5 = /\/EASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string6 = /\/eas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string7 = /\/owa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string8 = /\\EASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string9 = /\\eas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string10 = /\\owa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string11 = /\]\sNow\sspraying\sEAS\sportal\sat\shttps\:\/\/.{0,100}\/Microsoft\-Server\-ActiveSync/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string12 = /002fa7c3b308536f94ff10852afcfbb0285608d259a43277e69751ab7db48e04/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string13 = /fugawi\/EASSniper/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string14 = /Invoke\-PasswordSprayEAS/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string15 = /Invoke\-UsernameHarvestEAS/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string16 = /Password\sSpraying\sEAS\sat\shttps\:\/\// nocase ascii wide
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
