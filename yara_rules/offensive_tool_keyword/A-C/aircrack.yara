rule aircrack
{
    meta:
        description = "Detection patterns for the tool 'aircrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aircrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string1 = /\s\-r\sairolib\-db\s\/root\/wpa\.cap/ nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string2 = "airbase-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string3 = /aircrack\.txt/ nocase ascii wide
        // Description: WiFi security auditing tools suite.
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string4 = "Aircrack-ng" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string5 = "aircrack-ptw-" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string6 = "airdecap-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string7 = "aireplay-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string8 = "airgraph-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string9 = "airodump-ng " nocase ascii wide
        // Description: WiFi security auditing tools suite.
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string10 = "airodump-ng " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string11 = "airolib-ng airolib-db" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string12 = "airserv-ng -" nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string13 = "airtun-ng -a " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string14 = "besside-ng -W -v " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string15 = /easside\-ng\s\-.{0,1000}\s\-s\s127\.0\.0\.1/ nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string16 = "makeivs-ng -b " nocase ascii wide
        // Description: cracking Wi-Fi security including WEP and WPA/WPA2-PSK encryption
        // Reference: https://github.com/aircrack-ng/aircrack-ng
        $string17 = "wesside-ng -" nocase ascii wide

    condition:
        any of them
}
