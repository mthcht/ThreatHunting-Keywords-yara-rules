rule shutter
{
    meta:
        description = "Detection patterns for the tool 'shutter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shutter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string1 = /\\add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string2 = /\\shutter\-main\.zip/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string3 = /\\x64\\Debug\\Appblock\.exe/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string4 = "2164E6D9-6023-4932-A08F-7A5C15E2CA0B" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string5 = "326D0AB1-CF2F-4A9B-B612-04B62D4EBA89" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string6 = /appblock.{0,100}wfpsessionmanager\.obj/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string7 = /Appblock\.exe\s\-\-add/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string8 = /Appblock\.exe\s\-\-list/ nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string9 = "B52E2D10-A94A-4605-914A-2DCEF6A757EF" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string10 = "dsnezhkov/shutter" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string11 = "e11cbe43-b8bc-4042-a4a5-c8e960925c83" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string12 = "F3FEBDE7-FBC8-48EC-8F24-5F33B8ACFB2A" nocase ascii wide
        // Description: The goal of Shutter is to manage windows network stack communication via Windows Filtering Platform. Management can include blocking or permiting traffic based on IP or an executable that initiates or receives the traffic.
        // Reference: https://github.com/dsnezhkov/shutter
        $string13 = /\-\-filter\=add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide
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
