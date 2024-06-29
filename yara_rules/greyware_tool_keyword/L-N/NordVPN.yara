rule NordVPN
{
    meta:
        description = "Detection patterns for the tool 'NordVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NordVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN browser extension usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1 = /fjoaledfpmneenckfbpdfhkmimnjocfa/ nocase ascii wide
        // Description: OVPN configuration for nordvpn accessed within corporate network
        // Reference: https://nordvpn.com
        $string2 = /https\:\/\/nordvpn\.com.{0,1000}\/ovpn\/.{0,1000}\.ovpn/ nocase ascii wide

    condition:
        any of them
}
