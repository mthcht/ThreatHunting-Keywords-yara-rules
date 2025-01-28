rule Hak5_BashBunny
{
    meta:
        description = "Detection patterns for the tool 'Hak5 BashBunny' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 BashBunny"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: multi-function USB attack tool enabling automation attack payloads and various exploits by emulating trusted USB devices like keyboards - network adapters and mass storage devices
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /_USBSTOR\#Disk\&Ven_\&Prod_\&Rev_0000.{0,1000}53f56307\-b6bf\-11d0\-94f2\-00a0c91efb8b/

    condition:
        any of them
}
