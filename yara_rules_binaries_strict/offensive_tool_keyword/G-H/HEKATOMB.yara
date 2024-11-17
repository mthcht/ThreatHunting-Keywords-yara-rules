rule HEKATOMB
{
    meta:
        description = "Detection patterns for the tool 'HEKATOMB' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HEKATOMB"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string1 = /\sinstall\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string2 = /\.py\s.{0,100}\s\-debug\s\-dnstcp/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string3 = /\/exported_credentials\.csv/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string4 = /\[\+\]\sConnnecting\sto\sall\scomputers\sand\stry\sto\sget\sdpapi\sblobs\sand\smaster\skey\sfiles/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string5 = /\[\+\]\sScanning\scomputers\slist\son\sSMB\sport\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string6 = /\\exported_credentials\.csv/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string7 = /ed9d3ee993fe0a36bb7a7fce3940112ea29eccca58165738a758c58a3fe0ae54/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string8 = /hekatomb\s\-hashes\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string9 = /hekatomb\-.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string10 = /hekatomb.{0,100}\-hashes\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string11 = /hekatomb\-.{0,100}\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string12 = /hekatomb\.ad_ldap/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string13 = /hekatomb\@thiefin\.fr/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string14 = /it\swill\sextract\sdomain\scontroller\sprivate\skey\sthrough\sRPC\suses\sit\sto\sdecrypt\sall\scredentials/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string15 = /New\scredentials\sfound\sfor\suser\s.{0,100}\son\s/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string16 = /pacman\s\-S\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/ProcessusT/HEKATOMB
        $string17 = /poetry\srun\shekatomb/ nocase ascii wide
        // Description: Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them
        // Reference: https://github.com/Processus-Thief/HEKATOMB
        $string18 = /Processus\-Thief\/HEKATOMB/ nocase ascii wide
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
