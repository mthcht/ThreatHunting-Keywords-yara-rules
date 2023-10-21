rule UFONet
{
    meta:
        description = "Detection patterns for the tool 'UFONet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UFONet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UFONet - is a free software. P2P and cryptographic -disruptive toolkit- that allows to perform DoS and DDoS attacks. on the Layer 7 (APP/HTTP) through the exploitation of Open Redirect vectors on third-party websites to act as a botnet and on the Layer3 (Network) abusing the protocol.
        // Reference: https://github.com/epsylon/ufonet
        $string1 = /UFONet/ nocase ascii wide

    condition:
        any of them
}