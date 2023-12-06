rule theHarvester
{
    meta:
        description = "Detection patterns for the tool 'theHarvester' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "theHarvester"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: E-mails. subdomains and names Harvester.
        // Reference: https://github.com/laramies/theHarvester
        $string1 = /theHarvester/ nocase ascii wide

    condition:
        any of them
}
