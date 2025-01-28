rule DSInternals
{
    meta:
        description = "Detection patterns for the tool 'DSInternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DSInternals"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string1 = /\sDSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string2 = /\sGet\-ADReplAccount\s\-SamAccountName\s\'AZUREADSSOACC\$\'\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string3 = /\/DSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string4 = /\\DSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string5 = /DSInternals_v4\..{0,100}\.zip/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string6 = /Get\-ADDBAccount\s.{0,100}\s\-DataBasePath\s.{0,100}ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string7 = /Get\-ADDBAccount\s.{0,100}\s\-DBPath\s.{0,100}ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string8 = /Get\-ADDBAccount\s\-All\s\-DBPath\s.{0,100}\.ntds\.dit.{0,100}\s\-BootKey/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string9 = /Get\-ADDBAccount.{0,100}\s\-BootKey.{0,100}\s\-DataBasePath\s.{0,100}\.ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string10 = /Get\-ADDBAccount.{0,100}\s\-BootKey.{0,100}\s\-DBPath\s.{0,100}\.ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string11 = /Get\-ADDBAccount.{0,100}\s\-DataBasePath\s.{0,100}\.ntds\.dit.{0,100}\s\-BootKey/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string12 = "Get-ADReplAccount -All " nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string13 = "Import-Module DSInternals" nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string14 = "Install-Module -Name DSInternals" nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string15 = /Set\-SamAccountPasswordHash\s.{0,100}\s\-NTHash\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string16 = "Test-PasswordQuality -WeakPasswordHashesSortedFile " nocase ascii wide
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
