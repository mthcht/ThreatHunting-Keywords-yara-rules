rule ADAPE_Script
{
    meta:
        description = "Detection patterns for the tool 'ADAPE-Script' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADAPE-Script"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string1 = " \"Sniffy boi sniffin\"" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string2 = /\sADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string3 = /\$Kerberoast/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string4 = /\.ps1\s\-GPP\s\-PView\s\-Kerberoast/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string5 = /\.ps1\s\-PrivEsc/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string6 = /\/ADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string7 = /\/ADAPE\-Script\.git/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string8 = /\/Inveigh\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string9 = /\/PowerUp\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string10 = /\/PowerView\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string11 = /\/PrivEsc\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string12 = /\/PView\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string13 = /\\ADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string14 = /\\ExploitableSystem\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string15 = /\\PrivEsc\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string16 = /\\ShareFinder\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string17 = "7f99e59cb3242638aa4967180674b98dd770fae51a85ff364238faf52e02a586" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string18 = "Attemping WPAD, LLMNR, and NBTNS poisoning" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string19 = "Author: @haus3c" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string20 = "Collecting Privesc methods" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string21 = "function PrivEsc" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string22 = "Get-ExploitableSystem -Verbose" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string23 = /Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string24 = "hausec/ADAPE-Script" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string25 = /Import\-Module\s.{0,100}\/PView\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string26 = "Invoke-Kerberoast" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string27 = "Invoke-ShareFinder -CheckShareAccess" nocase ascii wide
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
