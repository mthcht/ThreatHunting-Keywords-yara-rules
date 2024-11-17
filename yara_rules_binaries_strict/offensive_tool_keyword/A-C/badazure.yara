rule badazure
{
    meta:
        description = "Detection patterns for the tool 'badazure' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badazure"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string1 = /\s\-Build\s\-NoAttackPaths/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string2 = /\/BadZure\.git/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string3 = /\/BadZure\// nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string4 = /\\BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string5 = /BadZure\-main/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string6 = /\-Build\s\$RandomAttackPath/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string7 = /Invoke\-BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string8 = /mvelazc0\/BadZure/ nocase ascii wide
        // Description: BadZure orchestrates the setup of Azure Active Directory tenants populating them with diverse entities while also introducing common security misconfigurations to create vulnerable tenants with multiple attack paths
        // Reference: https://github.com/mvelazc0/BadZure/
        $string9 = /\-RandomAttackPath\s\-Token/ nocase ascii wide
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
