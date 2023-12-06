rule nac_bypass
{
    meta:
        description = "Detection patterns for the tool 'nac_bypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nac_bypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: nac bypass - The basic requirement for an NAC bypass is access to a device that has already been authenticated. This device is used to log into the network and then smuggle in network packages from a different device. This involves placing the attackers system between the network switch and the authenticated device. One way to do this is with a Raspberry Pi and two network adapters
        // Reference: https://github.com/scipag/nac_bypass
        $string1 = /nac_bypass/ nocase ascii wide

    condition:
        any of them
}
