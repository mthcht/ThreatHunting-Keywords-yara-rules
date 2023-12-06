rule RogueSploit
{
    meta:
        description = "Detection patterns for the tool 'RogueSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RogueSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RogueSploit is an open source automated script made to create a Fake Acces Point. with dhcpd server. dns spoofing. host redirection. browser_autopwn1 or autopwn2 or beef+mitmf
        // Reference: https://github.com/h0nus/RogueSploit
        $string1 = /RogueSploit/ nocase ascii wide

    condition:
        any of them
}
