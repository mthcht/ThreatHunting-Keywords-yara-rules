rule I2P
{
    meta:
        description = "Detection patterns for the tool 'I2P' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "I2P"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: I2P - The Invisible Internet Project.
        // Reference: https://geti2p.net/
        $string1 = "i2pinstall" nocase ascii wide

    condition:
        any of them
}
