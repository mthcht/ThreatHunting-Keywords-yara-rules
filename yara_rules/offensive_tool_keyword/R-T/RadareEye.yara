rule RadareEye
{
    meta:
        description = "Detection patterns for the tool 'RadareEye' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RadareEye"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for especially scanning nearby devices and execute a given command on its own system while the target device comes in range.
        // Reference: https://github.com/souravbaghz/RadareEye
        $string1 = /\sradare\s.{0,1000}\:.{0,1000}\s\-ble/ nocase ascii wide
        // Description: Tool for especially scanning nearby devices and execute a given command on its own system while the target device comes in range.
        // Reference: https://github.com/souravbaghz/RadareEye
        $string2 = /souravbaghz\/RadareEye/ nocase ascii wide
        // Description: Tool for especially scanning nearby devices and execute a given command on its own system while the target device comes in range.
        // Reference: https://github.com/souravbaghz/RadareEye
        $string3 = /\.\/radare\s/ nocase ascii wide

    condition:
        any of them
}
