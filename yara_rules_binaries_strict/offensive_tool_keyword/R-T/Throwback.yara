rule Throwback
{
    meta:
        description = "Detection patterns for the tool 'Throwback' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Throwback"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string1 = /\/Throwback\.git/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string2 = "/ThrowbackDLL/" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string3 = /\\Throwback\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string4 = /\\Throwback\\Throwback\.h/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string5 = /\\ThrowbackDLL\\/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string6 = /\\Throwback\-master\.zip/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string7 = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string8 = "60C1DA68-85AC-43AB-9A2B-27FA345EC113" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string9 = "D7D20588-8C18-4796-B2A4-386AECF14256" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string10 = "DLL_METASPLOIT_ATTACH" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string11 = /include\s\\"ThrowbackDLL\.h\\"/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string12 = "silentbreaksec/Throwback" nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string13 = /tbMangler\.py\sencode\s/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string14 = /Throwback\\Base64_RC4\.h/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string15 = /throwback_x64\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string16 = /throwback_x86\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string17 = /throwBackDev\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string18 = /ThrowbackDLL\.cpp/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string19 = /ThrowbackDLL\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string20 = /ThrowbackDLL\.vcxproj/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string21 = "ZAQwsxcde321" nocase ascii wide
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
