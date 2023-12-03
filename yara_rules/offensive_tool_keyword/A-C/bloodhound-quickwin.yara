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
        $string1 = /.{0,1000}\sbhqc\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string2 = /.{0,1000}\/bhqc\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string3 = /.{0,1000}\/bloodhound\-quickwin\.git.{0,1000}/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string4 = /.{0,1000}bloodhound\-quickwin\-main.{0,1000}/ nocase ascii wide
        // Description: Simple script to extract useful informations from the combo BloodHound + Neo4j
        // Reference: https://github.com/kaluche/bloodhound-quickwin
        $string5 = /.{0,1000}kaluche\/bloodhound\-quickwin.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
