rule atexec_pro
{
    meta:
        description = "Detection patterns for the tool 'atexec-pro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string1 = /\satexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string2 = /\/atexec\-pro\.git/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string3 = /\/atexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string4 = /\/libs\/powershells\/upload\.ps1/
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string5 = /\/Rubeus\.exe/
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string6 = /\\atexec\-pro\.py/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string7 = /\\atexec\-pro\-main/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string8 = "10dbc6cb2d71505d7add5a2927228077142851657f2578b9c774656505338d32" nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string9 = /ATShell\s\(\%s\@\%s\)\>\s/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string10 = "dc5a1f72ecaa1cddb1df73ddd075819eb5d2d35f95ea11639cfa1e189ed15217" nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string11 = /impacket\.dcerpc/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string12 = /impacket\.krb5/ nocase ascii wide
        // Description: Fileless atexec for lateral movement
        // Reference: https://github.com/Ridter/atexec-pro
        $string13 = "Ridter/atexec-pro" nocase ascii wide

    condition:
        any of them
}
