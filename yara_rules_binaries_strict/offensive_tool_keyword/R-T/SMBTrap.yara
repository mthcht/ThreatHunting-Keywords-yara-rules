rule SMBTrap
{
    meta:
        description = "Detection patterns for the tool 'SMBTrap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBTrap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string1 = /\squickcrack\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string2 = /\sredirecttosmb\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string3 = /\ssmbtrap2\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string4 = /\ssmbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string5 = /\/quickcrack\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string6 = /\/redirecttosmb\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string7 = /\/SMBTrap\.git/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string8 = /\/smbtrap2\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string9 = /\/smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string10 = /\\quickcrack\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string11 = /\\redirecttosmb\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string12 = /\\smbtrap2\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string13 = /\\smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string14 = "06f43329147155af22520cda36202f9af0bd46b5e30b3d3f202d2a463aa2729d" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string15 = "432bb0868bd1152ce689dda88d274bb05671174c5c892c7db0575e50abcadf4c" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string16 = "c9def37771dabf11171830fdd27b3b751955f40c577fae3f9691188ed3f90b08" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string17 = "cylance/SMBTrap" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string18 = "de25283c258cc462a919df98ff3033b6f433cf0ab4d92e95a650099839c45e63" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string19 = "import try_to_crack_hash" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string20 = /redirecttosmb\.py\s/ nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string21 = "smbtrap-mitmproxy-inline" nocase ascii wide
        // Description: tool capturing authentication attempts and performing man-in-the-middle (MitM) attacks leveraging SMB services
        // Reference: https://github.com/cylance/SMBTrap
        $string22 = /try_to_crack_hash\(/ nocase ascii wide
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
