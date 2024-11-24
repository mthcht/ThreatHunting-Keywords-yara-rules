rule KRBUACBypass
{
    meta:
        description = "Detection patterns for the tool 'KRBUACBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KRBUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string1 = " KRBUACBypass" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string2 = /\.exe\sasktgs/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string3 = /\.exe\skrbscm/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string4 = "/KRBUACBypass" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string5 = /\/KRBUACBypass\.git/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string6 = /\\KRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string7 = /\\S4U\.Exe/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string8 = /\\SCMUACBypass\.cpp/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string9 = "4291df077f27794311313530ae25457a0fbad23d402c789ed3336ace4b64150c" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string10 = "5d2e0f4adc5e3bb1f154c9f22eee2cf15e0bb2c5815653e3d97cb1e97c99c326" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string11 = "881D4D67-46DD-4F40-A813-C9D3C8BE0965" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string12 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string13 = "c3c993b043322cac38d24d751229883227de36b38e2c8c1e0fc1ca0ff6f2fd9a" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string14 = /Copyright\s\(c\)\s2023\swhoamianony\.top/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string15 = "KRBUACBypass 1" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string16 = /KRBUACBypass\.csproj/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string17 = /KRBUACBypass\.exe/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string18 = /KRBUACBypass\.sln/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string19 = "KRBUACBypass/tarball" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string20 = "KRBUACBypass/zipball" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string21 = /lib\/Bruteforcer\.cs/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string22 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string23 = /Rubeus\/1\.0/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string24 = "UACBypassedService" nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string25 = "wh0amitz/KRBUACBypass" nocase ascii wide
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
