rule SecLists
{
    meta:
        description = "Detection patterns for the tool 'SecLists' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecLists"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SecLists is the security testers companion. Its a collection of multiple types of lists used during security assessments. collected in one place. List types include usernames. passwords. URLs. sensitive data patterns. fuzzing payloads. web shells. and many more. The goal is to enable a security tester to pull this repository onto a new testing box and have access to every type of list that may be needed.
        // Reference: https://github.com/danielmiessler/SecLists
        $string1 = /.{0,1000}SecLists.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
