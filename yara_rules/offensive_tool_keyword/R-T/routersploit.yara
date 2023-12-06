rule routersploit
{
    meta:
        description = "Detection patterns for the tool 'routersploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "routersploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices.exploits
        // Reference: https://github.com/threat9/routersploit
        $string1 = /routersploit/ nocase ascii wide

    condition:
        any of them
}
