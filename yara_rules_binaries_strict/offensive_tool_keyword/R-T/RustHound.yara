rule RustHound
{
    meta:
        description = "Detection patterns for the tool 'RustHound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string1 = /\s\-\-adcs\s\-\-old\-bloodhound\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string2 = /\s\-c\sDCOnly\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-o\s\/tmp/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string3 = /\srusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string4 = /\/rusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string5 = /\/RustHound\.git/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string6 = /\\rusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string7 = /\-\-collectionmethod\sDCOnly/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string8 = /OPENCYBER\-FR\/RustHound/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string9 = /rusthound\s.{0,100}\-\-domain/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string10 = /rusthound\s.{0,100}\-\-ldapfqdn\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string11 = /rusthound\s.{0,100}\-ldaps\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string12 = /rusthound\s\-c\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string13 = /rusthound\s\-d\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string14 = /rusthound\srusthound\slinux/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string15 = /rusthound\srusthound\swindows/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string16 = /rusthound.{0,100}\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string17 = /rusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string18 = /RustHound\-main/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string19 = /sharphound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string20 = /usr\/src\/rusthound\srusthound\s/ nocase ascii wide
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
