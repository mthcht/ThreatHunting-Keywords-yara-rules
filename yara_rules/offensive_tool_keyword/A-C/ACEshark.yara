rule ACEshark
{
    meta:
        description = "Detection patterns for the tool 'ACEshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACEshark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string1 = /\sACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string2 = /\.ACEshark\.log/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string3 = /\/\.ACEshark/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string4 = /\/ACEshark\.git/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string5 = /\/ACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string6 = /\\ACEshark\.log/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string7 = /\\ACEshark\.py/ nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string8 = "0e9af89e0f2faa8d7f92d6e9538e19f82c701c798031d890978845e388b85ba6" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string9 = "7fa5122ff9fabaf2676064087eacaf4a63b386bb27d50ac345ff4bdbe6a4f7d5" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string10 = "e07330a2c8c8678fce26c761437a3ed5cf38881baea403a376a5b3b9b5ef9d27" nocase ascii wide
        // Description: uncover potential privilege escalation vectors by analyzing windows service configurations and Access Control Entries
        // Reference: https://github.com/t3l3machus/ACEshark
        $string11 = "t3l3machus/ACEshark" nocase ascii wide

    condition:
        any of them
}
