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
        $string1 = /.{0,1000}\/ngrok\.exe.{0,1000}/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /.{0,1000}\\ngrok\.exe.{0,1000}/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /.{0,1000}LHOST\=0\.tcp\.ngrok\.io.{0,1000}/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4 = /.{0,1000}ngrok\stcp\s.{0,1000}/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string5 = /.{0,1000}tcp:\/\/0\.tcp\.ngrok\.io:.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
