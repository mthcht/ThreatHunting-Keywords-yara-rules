rule PowerForensics
{
    meta:
        description = "Detection patterns for the tool 'PowerForensics' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerForensics"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The purpose of PowerForensics is to provide an all inclusive framework for hard drive forensic analysis. PowerForensics currently supports NTFS and FAT file systems. and work has begun on Extended File System and HFS+ support.
        // Reference: https://github.com/Invoke-IR/PowerForensics
        $string1 = /PowerForensics/ nocase ascii wide

    condition:
        any of them
}
