rule Hak5_O_MG_Cable
{
    meta:
        description = "Detection patterns for the tool 'Hak5 O.MG Cable' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 O.MG Cable"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: USB cable with an advanced implant hidden inside
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /USB\\VID_10C4\\\&PID_EA60/ nocase ascii wide

    condition:
        any of them
}
