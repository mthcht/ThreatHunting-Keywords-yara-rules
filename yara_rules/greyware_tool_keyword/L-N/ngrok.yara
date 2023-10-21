rule ngrok
{
    meta:
        description = "Detection patterns for the tool 'ngrok' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ngrok"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /ngrok\stcp\s/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /tcp:\/\/0\.tcp\.ngrok\.io:/ nocase ascii wide

    condition:
        any of them
}