rule o365recon
{
    meta:
        description = "Detection patterns for the tool 'o365recon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365recon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string1 = /\.AzureAD\.Application_Owners\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string2 = /\.AzureAD\.DeviceList_Owners\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string3 = /\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string4 = /\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string5 = /\.O365\.Roles_Admins\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string6 = /\.O365\.Users_Detailed\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string7 = /\.O365\.Users_LDAP_details\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string8 = /\.O365\.Users_ProxyAddresses\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string9 = /\/o365recon\.git/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string10 = /\\.{0,100}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string11 = /\\.{0,100}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string12 = /\\.{0,100}\.O365\.Roles_Admins\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string13 = "49df12075c49bb956291cd11b2c53626174b4128309ada438d5d5e49265866f9" nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string14 = "JOB COMPLETE: GO GET YOUR LOOT!" nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string15 = "nyxgeek/o365recon" nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string16 = /o365recon\.ps1/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string17 = "o365recon-master" nocase ascii wide
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
