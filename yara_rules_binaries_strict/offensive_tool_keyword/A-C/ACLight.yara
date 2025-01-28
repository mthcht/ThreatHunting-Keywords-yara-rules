rule ACLight
{
    meta:
        description = "Detection patterns for the tool 'ACLight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACLight"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string1 = /\s\-\sSensitive\sAccounts\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string2 = /\/ACLight\.git/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string3 = "/ACLight/" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string4 = /\\scanACLsResults\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string5 = /Accounts\swith\sextra\spermissions\.txt/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string6 = /ACLight\.ps1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string7 = /ACLight\.psd1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string8 = /ACLight\.psm1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string9 = /ACLight2\.ps1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string10 = /ACLight2\.psd1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string11 = /ACLight2\.psm1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string12 = "ACLight-master" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string13 = "cyberark/ACLight" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string14 = /Execute\-ACLight\.bat/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string15 = /Execute\-ACLight2\.bat/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string16 = "Invoke-ACLcsvFileAnalysis" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string17 = /Invoke\-ACLScanner\s.{0,100}\s\-Filter\s/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string18 = /Invoke\-ACLScanner\s.{0,100}\s\-Name\s/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string19 = /Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string20 = /Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string21 = /Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string22 = "Start-ACLsAnalysis -Domain" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string23 = "Start-domainACLsAnalysis" nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string24 = "starting Multi-Layered ACLight scan" nocase ascii wide
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
