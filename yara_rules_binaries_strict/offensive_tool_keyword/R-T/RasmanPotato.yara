rule RasmanPotato
{
    meta:
        description = "Detection patterns for the tool 'RasmanPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RasmanPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string1 = /\srasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string2 = /\/rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string3 = /\/RasmanPotato/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string4 = /\[\!\]\sRasman\sservice\sis\snot\srunning\!/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string5 = /\[\+\]\sRasman\sservice\sis\serror/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string6 = /\[\+\]\sRasman\sservice\sis\srunning\!/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string7 = /\\RasMan\.cpp/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string8 = /\\rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string9 = /\\RasMan\.sln/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string10 = /\\RasmanPotato/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string11 = /5AC309CE\-1223\-4FF5\-AF84\-24BCD0B9E4DC/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string12 = /anypotato\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string13 = /Choose\sThe\sRPC\sFunction\s\[1\]VpnProtEngWinRtConnect\s\[2\]VpnProtEngGetInterface/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string14 = /dae7d1a42b0bb178bff2ca9729c31d59db045cd65db817cc9eca7a1721bc4c57/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string15 = /magicRasMan/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string16 = /Provided\sthat\sthe\scurrent\suser\shas\sthe\sSeImpersonate\sprivilege\,\sthis\stool\swill\shave\san\sescalation\sto\sSYSTEM/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string17 = /rasman.{0,100}whoami/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string18 = /RasMan\.vcxproj/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string19 = /rasman_c\.c/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string20 = /rasman_h\.h/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string21 = /RasmanPotato\-master/ nocase ascii wide
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
