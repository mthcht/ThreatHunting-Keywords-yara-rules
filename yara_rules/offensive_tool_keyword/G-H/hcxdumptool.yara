rule hcxdumptool
{
    meta:
        description = "Detection patterns for the tool 'hcxdumptool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hcxdumptool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Small tool to capture packets from wlan devices. After capturing. upload the uncleaned pcapng here (https://wpa-sec.stanev.org/?submit) to see if your ACCESS POINT or the CLIENT is vulnerable by using common wordlists. Convert the pcapng file to WPA-PBKDF2-PMKID+EAPOL hashline (22000) with hcxpcapngtool (hcxtools) and check if PreSharedKey or PlainMasterKey was transmitted unencrypted
        // Reference: https://github.com/ZerBea/hcxdumptool
        $string1 = /hcxdumptool/ nocase ascii wide

    condition:
        any of them
}
