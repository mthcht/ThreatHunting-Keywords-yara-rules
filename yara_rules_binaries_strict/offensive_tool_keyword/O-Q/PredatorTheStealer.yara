rule PredatorTheStealer
{
    meta:
        description = "Detection patterns for the tool 'PredatorTheStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PredatorTheStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string1 = /\/c\sping\s127\.0\.0\.1\s\&\&\sdel\s\\\\/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string2 = /\/PredatorTheStealer\.git/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string3 = /\\PredatorTheStealer\sDll\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string4 = /\\PredatorTheStealer\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string5 = /\\Stealing\.cpp/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string6 = /\\tor\\hidden_service\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string7 = /\\tor\\onion_router\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string8 = "190DFAEB-0288-4043-BE0E-3273FA653B52" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string9 = "30444d3f4f3bedc5d6aac36ad4deb9ce32d2ac91eb0b30e590f702b06825f372" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string10 = "99383be21201b97e739e06f5c89a815cd4a296030985505f238862aecbbb7a77" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string11 = /BTW\si\suse\sARCH\.\sA\s\-\sJeffrey\sEpstein\.\sR\s\-\sdidnt\.\sC\s\-\skill\.\sH\s\-\shimself/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string12 = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string13 = "SecUser1/PredatorTheStealer" nocase ascii wide
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
