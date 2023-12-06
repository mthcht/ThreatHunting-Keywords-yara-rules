rule chaos
{
    meta:
        description = "Detection patterns for the tool 'chaos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chaos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Chaos ransomware behavior
        // Reference: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/17/the-chaos-ransomware-can-be-ravaging
        $string1 = /C:\\Users\\.{0,1000}\\AppData\\Roaming\\svchost\.exe/ nocase ascii wide

    condition:
        any of them
}
