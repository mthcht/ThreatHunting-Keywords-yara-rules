rule DllProxy
{
    meta:
        description = "Detection patterns for the tool 'DllProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllProxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proxy your dll exports and add some spicy content at the same time
        // Reference: https://github.com/Iansus/DllProxy/
        $string1 = /.{0,1000}\.py\s.{0,1000}\.exe\s.{0,1000}NormalDLL\.dll.{0,1000}/ nocase ascii wide
        // Description: Proxy your dll exports and add some spicy content at the same time
        // Reference: https://github.com/Iansus/DllProxy/
        $string2 = /.{0,1000}\/DllProxy\.git.{0,1000}/ nocase ascii wide
        // Description: Proxy your dll exports and add some spicy content at the same time
        // Reference: https://github.com/Iansus/DllProxy/
        $string3 = /.{0,1000}dllproxy\.py.{0,1000}/ nocase ascii wide
        // Description: Proxy your dll exports and add some spicy content at the same time
        // Reference: https://github.com/Iansus/DllProxy/
        $string4 = /.{0,1000}DllProxy\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
