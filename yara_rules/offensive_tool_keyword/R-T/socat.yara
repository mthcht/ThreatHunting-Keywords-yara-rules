rule socat
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: listening on port 1337 -observed in variousmalware and poc explitation tools
        // Reference: N/A
        $string1 = "socat tcp4-listen:1337"

    condition:
        any of them
}
