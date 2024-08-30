rule Hak5_Lan_turtle
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Lan turtle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Lan turtle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ethernet extension device providing remote Access and MITM capabilities
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /USB\\VID_0BDA\&PID_8152\\00E04C361BDE/ nocase ascii wide
        // Description: ethernet extension device providing remote Access and MITM capabilities
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string2 = /USB\\VID_0BDA\&PID_8152\\00E04C3659E9/ nocase ascii wide

    condition:
        any of them
}
