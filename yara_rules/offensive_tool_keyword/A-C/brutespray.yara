rule brutespray
{
    meta:
        description = "Detection patterns for the tool 'brutespray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "brutespray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BruteSpray takes nmap GNMAP/XML output or newline seperated JSONS and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.
        // Reference: https://github.com/x90skysn3k/brutespray
        $string1 = /brutespray/ nocase ascii wide

    condition:
        any of them
}
