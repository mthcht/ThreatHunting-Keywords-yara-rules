rule ducky
{
    meta:
        description = "Detection patterns for the tool 'ducky' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ducky"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: rubber ducky
        // Reference: https://github.com/greghanley/ducky-decode-wiki/blob/master/Guide_Change_USB_VID_PID.wiki
        $string1 = /VID_03EB\&PID_2403\s/ nocase ascii wide

    condition:
        any of them
}
