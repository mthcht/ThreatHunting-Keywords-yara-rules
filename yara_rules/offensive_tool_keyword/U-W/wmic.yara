rule wmic
{
    meta:
        description = "Detection patterns for the tool 'wmic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: the threat actor deleted the SD value within the Tree registry path (hide scheduled task creation)
        // Reference: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        $string1 = /wmic\s\/namespace\:\\\\root\\default\spath\sstdRegProv\scall\sDeleteValue\s.{0,1000}SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\=.{0,1000}SD/ nocase ascii wide

    condition:
        any of them
}
