rule DRSAT
{
    meta:
        description = "Detection patterns for the tool 'DRSAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DRSAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string1 = /\/DGPOEdit\.zip/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string2 = /\/DRSAT\.exe/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string3 = /\/DRSAT\.git/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string4 = /\/DRSAT\-0\.2\.zip/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string5 = /\\DGPOEdit\.zip/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string6 = /\\DRSAT\.exe/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string7 = /\\DRSAT\-0\.2\.zip/ nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string8 = "25522ee1d92c2a6fb9d9dfa01c00ed08b9430cc573c9c4e4a829a1f0cb1670d7" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string9 = "28272a895f6980919f0a7acd8bfda4435c2a1a0b151c90f1113eda1eff12abd0" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string10 = "3a3b32c797443aeda45930d5b13f01d3a263ba4df42b2ed91da4a0e06e9590f7" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string11 = "59a95d191e08984a19d6fca6b65078e372c327624605b68e9c527205eaf455e5" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string12 = "74f34d98822c40027fa388f51791cec58f2bf71c47936616eca08489a4493f61" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string13 = "8af8c2cf6d5bb1a72a9d0ac3a534ba4d68ae6188aea4fbcf93c9fa5ebde47588" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string14 = "8FC203AA-8A90-4A15-B823-E2C3BC4DF0D6" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string15 = "c690e348e6aeb7b59b07a9872ea075ae73102081eeede8816a51534f77dbb62f" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string16 = "CCob/DRSAT" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string17 = "DB62BB65-0E29-4E95-BD4E-0AA543EF74B5" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string18 = "df6b380384faa29656ef09665f3ce25b350fb22712230f0abd8a79739218db15" nocase ascii wide
        // Description: Disconnected RSAT is a launcher for the official Group Policy Manager - Certificate Authority and Certificate Templates snap-in to bypass the domain joined requirement that is needed when using the official MMC snap-in. The tool works by injecting a C# library into MMC that will hook the various API calls to trick MMC into believing that the logged on user is a domain user. attackers can abuse Disconnected RSAT to interact with Active Directory (AD) environments from non-domain-joined machines
        // Reference: https://github.com/CCob/DRSAT
        $string19 = "DRSAT has injected hooks into process " nocase ascii wide
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
