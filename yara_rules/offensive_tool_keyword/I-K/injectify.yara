rule injectify
{
    meta:
        description = "Detection patterns for the tool 'injectify' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "injectify"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Perform advanced MiTM attacks on websites with ease.
        // Reference: https://github.com/samdenty/injectify
        $string1 = /injectify/ nocase ascii wide

    condition:
        any of them
}
