rule BloodHound_py
{
    meta:
        description = "Detection patterns for the tool 'BloodHound.py' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BloodHound.py"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/fox-it/BloodHound.py
        $string1 = /bloodhound\.py\s/ nocase ascii wide

    condition:
        any of them
}
