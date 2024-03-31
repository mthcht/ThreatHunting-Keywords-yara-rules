rule OPENVPN
{
    meta:
        description = "Detection patterns for the tool 'OPENVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OPENVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string1 = /\"\-\-\-\-\-BEGIN\sOpenVPN\sStatic\skey/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string2 = /\/openvpn\.exe/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string3 = /\\bin\\tapinstall\.exe/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string4 = /\\Licenses\\OpenVPN\.txt/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string5 = /\\openvpn\.exe/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string6 = /\\Program\sFiles\\TAP\-Windows\\/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string7 = /\\Root\\InventoryApplicationFile\\tap\-windows/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string8 = /\\SOFTWARE\\TAP\-Windows/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string9 = /\\tap\-windows\-.{0,1000}\.exe/ nocase ascii wide
        // Description: OpenVPN is a legitimate tool that might be used by an adversary to maintain persistence or exfiltrate data
        // Reference: https://openvpn.net/
        $string10 = /\>the\sopenvpn\sproject\</ nocase ascii wide

    condition:
        any of them
}
