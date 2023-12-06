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
        $string1 = /wirelesskeyview\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string2 = /wirelesskeyview\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string3 = /WirelessKeyView_x64\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string4 = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string5 = /wirelesskeyview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
