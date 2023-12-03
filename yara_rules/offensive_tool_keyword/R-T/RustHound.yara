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
        $string1 = /.{0,1000}\s\-\-adcs\s\-\-old\-bloodhound\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string2 = /.{0,1000}\srusthound\.exe.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string3 = /.{0,1000}\/rusthound\.exe.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string4 = /.{0,1000}\/RustHound\.git.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string5 = /.{0,1000}\\rusthound\.exe.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string6 = /.{0,1000}OPENCYBER\-FR\/RustHound.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string7 = /.{0,1000}rusthound\s.{0,1000}\-\-domain.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string8 = /.{0,1000}rusthound\s.{0,1000}\-\-ldapfqdn\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string9 = /.{0,1000}rusthound\s.{0,1000}\-ldaps\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string10 = /.{0,1000}rusthound\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string11 = /.{0,1000}rusthound.{0,1000}\s\-\-adcs\s\-\-dc\-only.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string12 = /.{0,1000}rusthound\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string13 = /.{0,1000}RustHound\-main.{0,1000}/ nocase ascii wide
        // Description: Active Directory data collector for BloodHound written in Rust
        // Reference: https://github.com/OPENCYBER-FR/RustHound
        $string14 = /.{0,1000}usr\/src\/rusthound\srusthound\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
