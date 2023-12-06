rule bloodhound
{
    meta:
        description = "Detection patterns for the tool 'bloodhound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodhound"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: he neo4j console command is used to start the Neo4j server in console mode. While it is not directly associated with a specific attack technique - it is often used in combination with tools like BloodHound to analyze and visualize data collected from Active Directory environments.
        // Reference: https://github.com/fox-it/BloodHound.py
        $string1 = /neo4j\sconsole/ nocase ascii wide

    condition:
        any of them
}
