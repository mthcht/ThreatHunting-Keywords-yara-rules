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
        $string1 = /\/hashcat\-rule\.git/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string2 = /\/password_ruled\.txt/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string3 = "clem9669/hashcat-rule"
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string4 = /clem9669_case\.rule/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string5 = /clem9669_large\.rule/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string6 = /clem9669_medium\.rule/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string7 = /clem9669_small\.rule/
        // Description: Rule for hashcat or john. Aiming to crack how people generate their password
        // Reference: https://github.com/clem9669/hashcat-rule
        $string8 = "hashcat-rule-master"

    condition:
        any of them
}
