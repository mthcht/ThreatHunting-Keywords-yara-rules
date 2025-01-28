rule Persistence_Accessibility_Features
{
    meta:
        description = "Detection patterns for the tool 'Persistence-Accessibility-Features' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Persistence-Accessibility-Features"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string1 = /\sstickykey\.ps1/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string2 = "# Sticky Keys backdoor exists" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string3 = /\/Persistence\-Accessibility\-Features\.git/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string4 = /\/stickykey\.ps1/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string5 = /\\stickykey\.ps1/ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string6 = "3c55b7897d676bc6ec3be27026b32389107e2bba443b52f25674fdc7e4229012" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string7 = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string8 = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string9 = "Ignitetechnologies/Persistence-Accessibility-Features" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string10 = "Persistence-Accessibility-Features-master" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string11 = "Sticky Key backdoor has been removed" nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string12 = /Sticky\sKeys\sbackdoor\sadded\./ nocase ascii wide
        // Description: automated sticky keys backdoor
        // Reference: https://github.com/Ignitetechnologies/Persistence-Accessibility-Features
        $string13 = "Sticky Keys backdoor does not exist, let's add it" nocase ascii wide
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
