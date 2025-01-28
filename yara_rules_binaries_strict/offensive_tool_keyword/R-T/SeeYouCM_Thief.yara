rule SeeYouCM_Thief
{
    meta:
        description = "Detection patterns for the tool 'SeeYouCM-Thief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SeeYouCM-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string1 = /\sthief\.py/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string2 = "/SeeYouCM-Thief" nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string3 = /\/thief\.py/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string4 = /cisco\-phone\-query\.sh/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string5 = "Credentials Found in Configurations!" nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string6 = /python.{0,100}http\:\/\/.{0,100}\:6970\/ConfigFileCacheList\.txt/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string7 = /python.{0,100}\'http\:\/\/.{0,100}SEP.{0,100}\:6970\/.{0,100}\.cnf\.xml/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string8 = /python.{0,100}https\:\/\/.{0,100}\:8443\/cucm\-uds\/users\?name\=/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string9 = "run thief:latest" nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string10 = /search_for_secrets\(/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string11 = /SeeYouCM\-Thief\.git/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string12 = "SeeYouCM-Thief-main" nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string13 = /thief\.py\s\-/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string14 = /tmp.{0,100}ciscophones\.tgz/ nocase ascii wide
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
