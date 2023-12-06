rule FluxionNetwork
{
    meta:
        description = "Detection patterns for the tool 'FluxionNetwork' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FluxionNetwork"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fluxion is a security auditing and social-engineering research tool. It is a remake of linset by vk496 with (hopefully) fewer bugs and more functionality. The script attempts to retrieve the WPA/WPA2 key from a target access point by means of a social engineering (phishing) attack. Its compatible with the latest release of Kali (rolling). Fluxions attacks' setup is mostly manual. but experimental auto-mode handles some of the attacks' setup parameters. Read the FAQ before requesting issues
        // Reference: https://github.com/FluxionNetwork/fluxion
        $string1 = /FluxionNetwork/ nocase ascii wide

    condition:
        any of them
}
