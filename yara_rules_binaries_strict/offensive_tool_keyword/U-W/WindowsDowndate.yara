rule WindowsDowndate
{
    meta:
        description = "Detection patterns for the tool 'WindowsDowndate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindowsDowndate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string1 = /\swindows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string2 = /\/windows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string3 = /\/WindowsDowndate\.git/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string4 = /\\windows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string5 = /\\WindowsDowndate\-main/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string6 = "0a0be178cd014f569eac8697ce355c7ceb59b7e1a3aaa18673a7ffde4a044c88" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string7 = "50eb54d0976374701c6051c23b993708,4d67d3d82b1adcc1b96e743e9b0efaaa8a566e3d,a34e71ededf334d3d6a480e3738c91fccbb4d2c1fbeec7192db9793a2541e8ca" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string8 = /CVE\-2021\-27090\-Secure\-Kernel\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string9 = /CVE\-2022\-34709\-Credential\-Guard\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string10 = /CVE\-2023\-21768\-AFD\-Driver\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string11 = "dab858feab4506727059fda4645865e2029892c6560704a7077433bab5d5ca0e" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string12 = /from\swindows_downdate\./ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string13 = /Hyper\-V\-Hypervisor\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string14 = /Kernel\-Suite\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string15 = /PPLFault\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string16 = "SafeBreach-Labs/WindowsDowndate" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string17 = "Starting Windows-Downdate" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string18 = /VBS\-UEFI\-Locks\-Bypass\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string19 = "Windows Downdate: Craft any downgrading Windows Updates" nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string20 = /windows_downdate\.exe/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string21 = "Windows-Downdate must be run as an Administrator" nocase ascii wide
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
