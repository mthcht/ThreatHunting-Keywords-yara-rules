rule wifijammer
{
    meta:
        description = "Detection patterns for the tool 'wifijammer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifijammer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: wifijammer
        // Reference: https://github.com/hash3liZer/wifijammer
        $string1 = /.{0,1000}hash3liZer\/wifijammer.{0,1000}/ nocase ascii wide
        // Description: wifijammer
        // Reference: https://github.com/DanMcInerney/wifijammer
        $string2 = /.{0,1000}wifijammer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
