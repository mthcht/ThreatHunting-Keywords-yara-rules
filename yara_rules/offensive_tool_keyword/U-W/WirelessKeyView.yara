rule WirelessKeyView
{
    meta:
        description = "Detection patterns for the tool 'WirelessKeyView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WirelessKeyView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string1 = /.{0,1000}wirelesskeyview\.exe.{0,1000}/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string2 = /.{0,1000}wirelesskeyview\.zip.{0,1000}/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string3 = /.{0,1000}WirelessKeyView_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string4 = /.{0,1000}wirelesskeyview\-no\-command\-line\.zip.{0,1000}/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string5 = /.{0,1000}wirelesskeyview\-x64\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
