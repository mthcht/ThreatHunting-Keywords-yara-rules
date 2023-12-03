rule hashcat_rule
{
    meta:
        description = "Detection patterns for the tool 'hashcat-rule' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat-rule"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string1 = /.{0,1000}\/hashcat\-rule\.git.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string2 = /.{0,1000}\/password_ruled\.txt.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string3 = /.{0,1000}clem9669\/hashcat\-rule.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string4 = /.{0,1000}clem9669_case\.rule.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string5 = /.{0,1000}clem9669_large\.rule.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string6 = /.{0,1000}clem9669_medium\.rule.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string7 = /.{0,1000}clem9669_small\.rule.{0,1000}/ nocase ascii wide
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string8 = /.{0,1000}hashcat\-rule\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
