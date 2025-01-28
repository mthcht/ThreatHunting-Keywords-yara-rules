rule Hak5_Screen_Crab
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Screen Crab' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Screen Crab"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: stealthy video man-in-the-middle HDMI implant
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /USB\\VID_18D1\&PID_4EE7\\KYLIN/ nocase ascii wide

    condition:
        any of them
}
