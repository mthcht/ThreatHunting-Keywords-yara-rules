rule Adcheck
{
    meta:
        description = "Detection patterns for the tool 'Adcheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adcheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string1 = /\sADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string2 = " --bloodhound-file " nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string3 = /\sGPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string4 = /\sSmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string5 = /\/ADcheck\.git/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string6 = /\/ADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string7 = /\/GPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string8 = /\/SmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string9 = /\\ADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string10 = /\\ADcheck\\Scripts\\activate/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string11 = /\\ADcheck\-main/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string12 = /\\GPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string13 = /\\SmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string14 = "29169875afabc27c2b4184d94689aae0955a6d8a7d11788fa3337efd807077ba" nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string15 = /admin_can_be_delegated\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string16 = /asreproast\(/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string17 = "bdc2c691a61df0926160a728c8419244fa2a1523bf3a3c61a353afa78d80cbfe" nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string18 = "CobblePot59/ADcheck" nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string19 = "f4a493d7a8c194fa599d23d6302a5bd7092fe01a60d7803688546b8cb68d8bf4" nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string20 = /kerberoast\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string21 = /krbtgt_password_age\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string22 = "python -m venv ADcheck" nocase ascii wide
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
