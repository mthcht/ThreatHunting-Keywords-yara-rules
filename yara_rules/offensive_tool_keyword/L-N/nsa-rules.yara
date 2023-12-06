rule nsa_rules
{
    meta:
        description = "Detection patterns for the tool 'nsa-rules' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsa-rules"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password cracking rules and masks for hashcat that I generated from cracked passwords.
        // Reference: https://github.com/NSAKEY/nsa-rules
        $string1 = /\spwcrack\.sh/ nocase ascii wide
        // Description: Password cracking rules and masks for hashcat that I generated from cracked passwords.
        // Reference: https://github.com/NSAKEY/nsa-rules
        $string2 = /\/nsa\-rules\.git/ nocase ascii wide
        // Description: Password cracking rules and masks for hashcat that I generated from cracked passwords.
        // Reference: https://github.com/NSAKEY/nsa-rules
        $string3 = /\/pwcrack\.sh/ nocase ascii wide
        // Description: Password cracking rules and masks for hashcat that I generated from cracked passwords.
        // Reference: https://github.com/NSAKEY/nsa-rules
        $string4 = /NSAKEY\/nsa\-rules/ nocase ascii wide
        // Description: Password cracking rules and masks for hashcat that I generated from cracked passwords.
        // Reference: https://github.com/NSAKEY/nsa-rules
        $string5 = /nsa\-rules\-master/ nocase ascii wide

    condition:
        any of them
}
