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
        $string2 = /\srusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string3 = /\/rusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string4 = /\/RustHound\.git/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string5 = /\\rusthound\.exe/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string6 = /OPENCYBER\-FR\/RustHound/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string7 = /rusthound\s.*\-\-domain/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string8 = /rusthound\s.*\-\-ldapfqdn\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string9 = /rusthound\s.*\-ldaps\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string10 = /rusthound\s\-d\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string11 = /rusthound.*\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string12 = /RustHound\-main/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string13 = /usr\/src\/rusthound\srusthound\s/ nocase ascii wide

    condition:
        any of them
}