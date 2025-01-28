rule ThievingFox
{
    meta:
        description = "Detection patterns for the tool 'ThievingFox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThievingFox"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string1 = " --mobaxterm-poison-hkcr" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string2 = " --mstsc-poison-hkcr" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string3 = " --rdcman-poison-hkcr" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string4 = /\sSuccessfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string5 = /\sThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string6 = /\/logonuifox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string7 = /\/mstscfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string8 = /\/rdcmanfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string9 = /\/ThievingFox\.git/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string10 = /\/ThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string11 = /\\consentfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string12 = /\\KeePassFox\.csproj/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string13 = /\\KeePassFox\.sln/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string14 = /\\logonuifox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string15 = /\\mstscfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string16 = /\\rdcmanfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string17 = /\\ThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string18 = "28e90498456b5e0866fde4371f560e5673f75e761855b73b063eadaef39834d2" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string19 = "6A5942A4-9086-408E-A9B4-05ABC34BFD58" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string20 = "b99078f0abc00a579cf218f3ed1d1ca89fffd5c328239303bf98432732df00f0" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string21 = "Compiling mstscax dll proxy" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string22 = /Compiling\sproxy\sargon2\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string23 = "f6f082606e6725734c4ad3fef4e9d1ae5669ebab5c9085e6ab3b409793ca2000" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string24 = "Found a sideloaded DLL, assuming injection already performed" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string25 = /keepassxcfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string26 = /mobaxtermfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string27 = "Slowerzs/ThievingFox" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string28 = /Successfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string29 = /Successfully\spoisonned\sconsent\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string30 = /Successfully\spoisonned\sLogonUI\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string31 = "Successfully poisonned MobaXTerm" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string32 = /Successfully\spoisonned\smstsc\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string33 = /Successfully\spoisonned\sRDCMan\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string34 = "Sucessfully performed AppDomainInjection for KeePass" nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string35 = /ThievingFox\.py\s/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string36 = "uploading mstscax proxy dll to " nocase ascii wide
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
