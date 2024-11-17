rule ADACLScanner
{
    meta:
        description = "Detection patterns for the tool 'ADACLScanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADACLScanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string1 = /\.ps1\s\-Base\s.{0,100}OU\=.{0,100}DC\=.{0,100}\s\-Credentials\s.{0,100}\s\-Server\s/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string2 = /\/ADACLScanner\.git/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string3 = /_adAclOutput.{0,100}\.csv/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string4 = /_adAclOutput.{0,100}\.csv/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string5 = /_adAclOutput.{0,100}\.csv/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string6 = /_adAclOutput.{0,100}\.csv/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string7 = /_adAclOutput.{0,100}\.csv/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string8 = /_adAclOutput.{0,100}\.xlsx/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string9 = /3ECA4B56CE358B13E1128A1E6149ED07CA0A8C55997B50A1E2C4EA46BD586B84/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string10 = /4E0CA74F5E074DFF389263D15E3913750EB437C1C3CD3B212C2998352023B980/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string11 = /555662D4CCBB940D87869E6295EC7CC74BB85D8C8FC5916EC34D1226704578C5/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string12 = /6973A4710FD88D32D47F4523E7EC098EF407F8ECED4B34AF6D3759CE1696EF19/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string13 = /6BF82CF9845C649557FC02D1E3D0B6A9FB4F827CC7815BF477DD0CB51246DA45/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string14 = /9AC25A8825407CCB6089BC7A2DF530D1830795B7E71A981ECEE4C5F48387B37A/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string15 = /ADACLScan\.ps1/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string16 = /ADACLScanner/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string17 = /ADACLScanner\-master/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string18 = /B5A3FA5B3DA95F6AA7556EE2BC62E5D290F72453105EF88E170174994DDA2650/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string19 = /canix1\/ADACLScanner/ nocase ascii wide
        // Description: A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory .
        // Reference: https://github.com/canix1/ADACLScanner
        $string20 = /F8E0A09D99FF46019C0C3F2B725E9887D9AE53CB7FAD0BB233BC8612C2CA51F2/ nocase ascii wide
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
