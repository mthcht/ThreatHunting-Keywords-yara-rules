rule debugdfs
{
    meta:
        description = "Detection patterns for the tool 'debugdfs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "debugdfs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Linux SIEM Bypass with debugdfs shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string1 = /debugfs\s\/dev\// nocase ascii wide

    condition:
        any of them
}
