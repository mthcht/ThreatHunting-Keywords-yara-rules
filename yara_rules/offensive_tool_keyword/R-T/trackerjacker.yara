rule trackerjacker
{
    meta:
        description = "Detection patterns for the tool 'trackerjacker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "trackerjacker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Like nmap for mapping wifi networks you're not connected to. Maps and tracks wifi networks and devices through raw 802.11 monitoring.
        // Reference: https://github.com/calebmadrigal/trackerjacker
        $string1 = /\/trackerjacker/ nocase ascii wide

    condition:
        any of them
}
