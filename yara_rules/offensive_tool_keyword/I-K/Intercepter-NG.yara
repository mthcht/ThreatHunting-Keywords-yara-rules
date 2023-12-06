rule Intercepter_NG
{
    meta:
        description = "Detection patterns for the tool 'Intercepter-NG' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Intercepter-NG"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: android wifi sniffer
        // Reference: https://github.com/intercepter-ng
        $string1 = /Intercepter\-NG/ nocase ascii wide

    condition:
        any of them
}
