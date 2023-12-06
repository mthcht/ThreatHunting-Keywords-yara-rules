rule truffleHog
{
    meta:
        description = "Detection patterns for the tool 'truffleHog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "truffleHog"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string1 = /truffleHog/ nocase ascii wide

    condition:
        any of them
}
