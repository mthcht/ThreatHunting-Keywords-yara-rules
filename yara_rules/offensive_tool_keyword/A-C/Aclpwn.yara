rule Aclpwn
{
    meta:
        description = "Detection patterns for the tool 'Aclpwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aclpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Aclpwn.py is a tool that interacts with BloodHound to identify and exploit ACL based privilege escalation paths. It takes a starting and ending point and will use Neo4j pathfinding algorithms to find the most efficient ACL based privilege escalation path. Aclpwn.py is similar to the PowerShell based Invoke-Aclpwn
        // Reference: https://github.com/fox-it/aclpwn.py
        $string1 = /aclpwn\.py/ nocase ascii wide

    condition:
        any of them
}
