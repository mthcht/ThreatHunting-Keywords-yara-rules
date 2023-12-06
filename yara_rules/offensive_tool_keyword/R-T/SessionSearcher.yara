rule SessionSearcher
{
    meta:
        description = "Detection patterns for the tool 'SessionSearcher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionSearcher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/SessionSearcher
        $string1 = /\/SessionSearcher\.exe/ nocase ascii wide
        // Description: Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/SessionSearcher
        $string2 = /\\SessionSearcher\.csproj/ nocase ascii wide
        // Description: Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/SessionSearcher
        $string3 = /\\SessionSearcher\.exe/ nocase ascii wide

    condition:
        any of them
}
