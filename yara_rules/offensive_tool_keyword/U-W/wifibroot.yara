rule wifibroot
{
    meta:
        description = "Detection patterns for the tool 'wifibroot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifibroot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string1 = /.{0,1000}\/WiFiBroot.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string2 = /.{0,1000}\-\-mode\s3\s\-\-type\shandshake\s\-\-essid\s.{0,1000}\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.cap.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string3 = /.{0,1000}\-\-mode\s3\s\-\-type\spmkid\s\-\-verbose\s\-d\sdicts\/.{0,1000}\s\-\-read\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string4 = /.{0,1000}wifibroot\.py.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string5 = /.{0,1000}wireless\/captures\.py.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string6 = /.{0,1000}wireless\/cracker\.py.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string7 = /.{0,1000}wireless\/pmkid\.py.{0,1000}/ nocase ascii wide
        // Description: A Wireless (WPA/WPA2) Pentest/Cracking tool. Captures & Crack 4-way handshake and PMKID key. Also. supports a deauthentication/jammer mode for stress testing
        // Reference: https://github.com/hash3liZer/WiFiBroot
        $string8 = /.{0,1000}wireless\/sniper\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
