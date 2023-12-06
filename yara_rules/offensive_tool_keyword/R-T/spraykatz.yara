rule spraykatz
{
    meta:
        description = "Detection patterns for the tool 'spraykatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraykatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string1 = /spraykatz/ nocase ascii wide

    condition:
        any of them
}
