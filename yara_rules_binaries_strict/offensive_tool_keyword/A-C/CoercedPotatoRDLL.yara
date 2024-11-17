rule CoercedPotatoRDLL
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotatoRDLL' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotatoRDLL"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string1 = /\sCoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string2 = /\sspawn\sC\:\\Windows\\Temp\\beacon\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string3 = /\sspawn\sC\:\\Windows\\Temp\\loader\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string4 = /\/CoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string5 = /\/CoercedPotatoRDLL\.git/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string6 = /\[\+\]\sExploit\sworked.{0,100}\sit\sshould\sexecute\syour\scommand\sas\sSYSTEM\!/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string7 = /\\\\\.\\pipe\\coerced\\pipe\\spoolss/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string8 = /\\127\.0\.0\.1\/pipe\/coerced/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string9 = /\\CoercedPotato\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string10 = /337ED7BE\-969A\-40C4\-A356\-BE99561F4633/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string11 = /CoercedPotato\sspawn\s/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string12 = /CoercedPotato\.exe/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string13 = /CoercedPotatoRDLL\-main/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string14 = /CoercePotato\scoerce/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string15 = /dist\/coercedpotato\.cna/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string16 = /ReflectiveDLLInjection\.h/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string17 = /ReflectiveLoader\.cpp/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string18 = /sokaRepo\/CoercedPotatoRDLL/ nocase ascii wide
        // Description: Reflective DLL to privesc from NT Service to SYSTEM using SeImpersonateToken privilege
        // Reference: https://github.com/sokaRepo/CoercedPotatoRDLL
        $string19 = /Spawn\sCoercedPotato\sas\sa\sReflective\sDLL/ nocase ascii wide
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
