rule _12ft_io
{
    meta:
        description = "Detection patterns for the tool '12ft.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "12ft.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Attackers can use 12ft.io to masquerade their domain for phishing purposes.
        // Reference: https://12ft.io/
        $string1 = /https\:\/\/12ft\.io\/api\/proxy\?q\=http/ nocase ascii wide
        // Description: Attackers can use 12ft.io to masquerade their domain for phishing purposes.
        // Reference: https://12ft.io/
        $string2 = /https\:\/\/12ft\.io\/proxy\?q\=/ nocase ascii wide

    condition:
        any of them
}
