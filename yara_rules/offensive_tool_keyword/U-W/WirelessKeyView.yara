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
        $string1 = " /GetKeys WirelessKeyView" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string2 = ">Extracts wireless keys stored by Windows<" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string3 = ">Wireless Key View<" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string4 = "19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string5 = "31ee7ee1add800239003806829b825cadc5b95797c11e33cf6b691571c1e2069" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string6 = "5d17e9dd54752bf9071caeccace27123897fe33de26db8c6f3e544abd11f7cb2" nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string7 = /wirelesskeyview\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string8 = /wirelesskeyview\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string9 = /wirelesskeyview\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string10 = /wirelesskeyview\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string11 = /WirelessKeyView_x64\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string12 = /WirelessKeyView_x64\.exe/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string13 = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string14 = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string15 = /wirelesskeyview\-x64\.zip/ nocase ascii wide
        // Description: WirelessKeyView recovers all wireless network security keys/passwords (WEP/WPA) stored in your computer 
        // Reference: https://www.nirsoft.net/utils/wireless_key.html
        $string16 = /wirelesskeyview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
