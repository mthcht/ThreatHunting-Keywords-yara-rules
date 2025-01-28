rule Arduino_Pro_Micro
{
    meta:
        description = "Detection patterns for the tool 'Arduino Pro Micro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Arduino Pro Micro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keystroke injection tool
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /USB\\VID_2341\&PID_8037/ nocase ascii wide

    condition:
        any of them
}
