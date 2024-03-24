rule _0bin_net
{
    meta:
        description = "Detection patterns for the tool '0bin.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0bin.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Accessing a paste on 0bin.net
        // Reference: https://0bin.net
        $string1 = /0bin\s\-\sencrypted\spastebin/ nocase ascii wide
        // Description: Accessing a paste on 0bin.net
        // Reference: https://0bin.net
        $string2 = /A\sclient\sside\sencrypted\sPasteBin/ nocase ascii wide
        // Description: Accessing a paste on 0bin.net
        // Reference: https://0bin.net
        $string3 = /https\:\/\/0bin\.net\/paste\/.{0,1000}\+/ nocase ascii wide
        // Description: Creating a paste on 0bin.net
        // Reference: https://0bin.net
        $string4 = /https\:\/\/0bin\.net\/paste\/create/ nocase ascii wide

    condition:
        any of them
}
