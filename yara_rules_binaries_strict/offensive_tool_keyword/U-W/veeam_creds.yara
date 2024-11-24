rule veeam_creds
{
    meta:
        description = "Detection patterns for the tool 'veeam-creds' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "veeam-creds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string1 = /\$VeaamRegPath.{0,100}SqlDatabaseName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string2 = /\$VeaamRegPath.{0,100}SqlInstanceName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string3 = /\$VeaamRegPath.{0,100}SqlServerName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string4 = /\/veeam\-creds\.git/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string5 = /\\veeam\-creds\\/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string6 = "4d9b2297358dbe1d72168480ab67ef7b992c2b84d4f09d71d906c941523f7b74" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string7 = "5c7e09b63bd99851d8b93241f3907917c07af3903aa024da0bd549ae1fc373f7" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string8 = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string9 = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string10 = "dd05c2d2a5d00de8f4ef3dd6d8e2304d2ecb3787e97edd0e38867d047b0936a0" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string11 = "Here are some passwords for you, have fun:" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string12 = "Invoke-VeeamGetCreds" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string13 = "sadshade/veeam-creds" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string14 = "veeam-creds-main" nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string15 = /Veeam\-Get\-Creds\.ps1/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string16 = /VeeamGetCreds\.yaml/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string17 = /veeampot\.py/ nocase ascii wide
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
