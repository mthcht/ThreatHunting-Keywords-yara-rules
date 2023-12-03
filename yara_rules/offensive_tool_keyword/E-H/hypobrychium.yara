rule hypobrychium
{
    meta:
        description = "Detection patterns for the tool 'hypobrychium' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypobrychium"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hypobrychium AV/EDR Bypass
        // Reference: https://github.com/foxlox/hypobrychium
        $string1 = /.{0,1000}\/hypobrychium\.git.{0,1000}/ nocase ascii wide
        // Description: hypobrychium AV/EDR Bypass
        // Reference: https://github.com/foxlox/hypobrychium
        $string2 = /.{0,1000}foxlox\/hypobrychium.{0,1000}/ nocase ascii wide
        // Description: hypobrychium AV/EDR Bypass
        // Reference: https://github.com/foxlox/hypobrychium
        $string3 = /.{0,1000}hypobrychium\.exe.{0,1000}/ nocase ascii wide
        // Description: hypobrychium AV/EDR Bypass
        // Reference: https://github.com/foxlox/hypobrychium
        $string4 = /.{0,1000}hypobrychium\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
