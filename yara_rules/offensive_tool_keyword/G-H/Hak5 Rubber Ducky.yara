rule Hak5_Rubber_Ducky
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Rubber Ducky' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Rubber Ducky"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keystroke injection tool
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /HID\\VID_03EB\&PID_2401\&REV_0100/ nocase ascii wide
        // Description: keystroke injection tool
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string2 = /HID\\VID_03EB\&PID_2422\&REV_0100/ nocase ascii wide
        // Description: keystroke injection tool	
        // Reference: https://github.com/greghanley/ducky-decode-wiki/blob/master/Guide_Change_USB_VID_PID.wiki
        $string3 = "VID_03EB&PID_2403" nocase ascii wide

    condition:
        any of them
}
