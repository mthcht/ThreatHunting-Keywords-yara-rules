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
        $string2 = /\s\-c\sDCOnly\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-o\s\/tmp/ nocase ascii wide
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
        $string9 = /rusthound\s.{0,1000}\-\-domain/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string10 = /rusthound\s.{0,1000}\-\-ldapfqdn\s/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string11 = /rusthound\s.{0,1000}\-ldaps\s/ nocase ascii wide
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
        $string16 = /rusthound.{0,1000}\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
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

    condition:
        any of them
}
