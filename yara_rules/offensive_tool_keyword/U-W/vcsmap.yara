rule vcsmap
{
    meta:
        description = "Detection patterns for the tool 'vcsmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vcsmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: vcsmap is a plugin-based tool to scan public version control systems (currently GitHub and possibly Gitlab soon) for sensitive information like access tokens and credentials.
        // Reference: https://github.com/melvinsh/vcsmap
        $string1 = "vcsmap" nocase ascii wide

    condition:
        any of them
}
