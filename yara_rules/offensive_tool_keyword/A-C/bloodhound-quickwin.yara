rule bloodhound_quickwin
{
    meta:
        description = "Detection patterns for the tool 'bloodhound-quickwin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodhound-quickwin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string1 = /\sbhqc\.py\s\-/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string2 = /\/bhqc\.py\s\-/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string3 = /\/bloodhound\-quickwin\.git/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string4 = /bloodhound\-quickwin\-main/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string5 = /kaluche\/bloodhound\-quickwin/ nocase ascii wide

    condition:
        any of them
}
