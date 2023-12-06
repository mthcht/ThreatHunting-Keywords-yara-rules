rule yodo
{
    meta:
        description = "Detection patterns for the tool 'yodo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yodo"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool proves how easy it is to become root via limited sudo permissions. via dirty COW or using Pa(th)zuzu. 
        // Reference: https://github.com/b3rito/yodo
        $string1 = /b3rito.{0,1000}yodo/ nocase ascii wide

    condition:
        any of them
}
