rule Nordic_NRF52840
{
    meta:
        description = "Detection patterns for the tool 'Nordic NRF52840' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nordic NRF52840"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Logitech Unifying impersonator - used for keystroke injections
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /USB\\VID_1915\&PID_520C\&MI_00\\6\&20A3E423/ nocase ascii wide

    condition:
        any of them
}
