rule Mimikatz
{
    meta:
        description = "Detection patterns for the tool 'Mimikatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mimikatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Scripts focused on Post-Exploitation Capabilities
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string1 = /Invoke\-RemoteMimikatz/ nocase ascii wide

    condition:
        any of them
}
