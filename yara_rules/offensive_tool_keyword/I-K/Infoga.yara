rule Infoga
{
    meta:
        description = "Detection patterns for the tool 'Infoga' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Infoga"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Email Information Gathering.
        // Reference: https://github.com/m4ll0k/Infoga
        $string1 = "/Infoga"

    condition:
        any of them
}
