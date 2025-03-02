rule _0day_today
{
    meta:
        description = "Detection patterns for the tool '0day.today' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0day.today"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a platform providing exploit code (free and paid)
        // Reference: https://0day.today/
        $string1 = /https\:\/\/0day\.today\/exploit\// nocase ascii wide

    condition:
        any of them
}
