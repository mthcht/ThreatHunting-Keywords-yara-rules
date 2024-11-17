rule cuddlephish
{
    meta:
        description = "Detection patterns for the tool 'cuddlephish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cuddlephish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string1 = /\/cuddlephish\.git/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string2 = /\/cuddlephish\.html/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string3 = /\/user_data\/.{0,100}\/keylog\.txt/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string4 = /57a0a978ab19598abf7185762834fef1b4dbd4db30d2fb85d411a0e22821df25/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string5 = /AAABAAMAEBAAAAEAIABoBAAANgAAACAgAAABACAAKBEAAJ4EAAAwMAAAAQAgAGgmAADGFQAAKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP39/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string6 = /browser\.keylog_file\.write/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string7 = /cuddlephish.{0,100}stealer\.js/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string8 = /cuddlephish\-main/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string9 = /fkasler\/cuddlephish/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string10 = /http\:\/\/localhost\:58082\/broadcast\?id\=/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string11 = /listen\(58082.{0,100}\s\'0\.0\.0\.0\'/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string12 = /node\sstealer\.js\s/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string13 = /ws\:\/\/localhost\:58082/ nocase ascii wide
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
