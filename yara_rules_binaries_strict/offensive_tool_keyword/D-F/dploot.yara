rule dploot
{
    meta:
        description = "Detection patterns for the tool 'dploot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dploot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string1 = " -m rdrleakdiag -M masterkeys" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string2 = /\/dploot\.git/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string3 = /\]\sTriage\sSCCM\sSecrets/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string4 = /decrypt_chrome_password\(/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string5 = "dploot -" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string6 = "dploot sccm -d" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string7 = /dploot.{0,100}backupkey/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string8 = /dploot.{0,100}browser/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string9 = /dploot.{0,100}certificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string10 = /dploot.{0,100}credentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string11 = /dploot.{0,100}machinecertificates/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string12 = /dploot.{0,100}machinecredentials/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string13 = /dploot.{0,100}machinemasterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string14 = /dploot.{0,100}machinevaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string15 = /dploot.{0,100}masterkeys/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string16 = /dploot.{0,100}vaults/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string17 = /dploot.{0,100}wifi/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string18 = /dploot\.lib\.dpapi/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string19 = /dploot\.lib\.smb/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string20 = /dploot\.triage\./ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string21 = /dploot\.triage\.sccm\simport\sSCCMTriage/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string22 = /dploot\/releases\/download\/.{0,100}\/dploot/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string23 = "dploot_linux_adm64"
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string24 = /dploot\-main\.zip/ nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string25 = "Dump looted SCCM secrets to specified directory" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string26 = "Dump SCCM secrets from WMI requests results" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string27 = "import DPLootSMBConnection" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string28 = "install dploot" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string29 = "lsassy -" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string30 = "Password:Waza1234" nocase ascii wide
        // Description: DPAPI looting remotely in Python
        // Reference: https://github.com/zblurx/dploot
        $string31 = "zblurx/dploot" nocase ascii wide
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
