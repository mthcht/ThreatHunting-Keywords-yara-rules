rule localpotato
{
    meta:
        description = "Detection patterns for the tool 'localpotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localpotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string1 = /\s\/potato\.local/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string2 = /\/evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string3 = /\/LocalPotato\.git/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string4 = /\/webdavshare\/potato\.local/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string5 = /\[\!\]\sHTTP\sreflected\sDCOM\sauthentication\sfailed\s/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string6 = /\[\!\]\sSMB\sreflected\sDCOM\sauthentication\sfailed/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string7 = /\[\+\]\sHTTP\sClient\sAuth\sContext\sswapped\swith\sSYSTEM\s/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string8 = /\[\+\]\sHTTP\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string9 = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string10 = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string11 = /\\evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string12 = /\\LocalPotato\\.{0,100}\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string13 = /\\LocalPotato\\.{0,100}\.exe/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string14 = /\\PotatoTrigger\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string15 = /\]\sReceived\sDCOM\sNTLM\stype\s3\sauthentication\sfrom\sthe\sprivileged\sclient/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string16 = "1B3C96A3-F698-472B-B786-6FED7A205159" nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string17 = "-c 854A20FB-2D44-457D-992F-EF13785D2B51" nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string18 = /DCOMReflection\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string19 = "decoder-it/LocalPotato" nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string20 = /IUnknownObj\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string21 = /LocalPotato\s\(aka\sCVE\-2023\-21746\s\&\sHTTP\/WebDAV\)/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string22 = "localpotato -i" nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string23 = /LocalPotato\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string24 = /LocalPotato\.exe/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string25 = /LocalPotato\.html/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string26 = /LocalPotato\.sln/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string27 = /LocalPotato\.vcxproj/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string28 = /LocalPotato\.zip/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string29 = "LocalPotato-master" nocase ascii wide
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
