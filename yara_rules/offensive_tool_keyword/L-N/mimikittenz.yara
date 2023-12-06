rule mimikittenz
{
    meta:
        description = "Detection patterns for the tool 'mimikittenz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikittenz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes mimikittenz can also easily extract other kinds of juicy info from target processes using regex patterns including but not limited Encryption Keys & All the other goodstuff
        // Reference: https://github.com/orlyjamie/mimikittenz
        $string1 = /mimikittenz/ nocase ascii wide

    condition:
        any of them
}
