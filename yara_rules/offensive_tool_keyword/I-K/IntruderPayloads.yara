rule IntruderPayloads
{
    meta:
        description = "Detection patterns for the tool 'IntruderPayloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IntruderPayloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of Burpsuite Intruder payloads. BurpBounty payloads (https://github.com/wagiro/BurpBounty). fuzz lists and pentesting methodologies. To pull down all 3rd party repos. run install.sh in the same directory of the IntruderPayloads folder.
        // Reference: https://github.com/1N3/IntruderPayloads
        $string1 = /IntruderPayloads/ nocase ascii wide

    condition:
        any of them
}
