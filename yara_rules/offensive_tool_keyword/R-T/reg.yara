rule reg
{
    meta:
        description = "Detection patterns for the tool 'reg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: the threat actor deleted the SD value within the Tree registry path (hide scheduled task creation)
        // Reference: https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
        $string1 = /reg\sdelete\s.{0,1000}HKEY_LOCAL_MACHINE\\SOFTWARE\\YourSoftware\\Schedule\\TaskCache\\Tree\\.{0,1000}\sSD\s/ nocase ascii wide
        // Description: Delete run box history
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string2 = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\s\/va\s\/f/ nocase ascii wide

    condition:
        any of them
}
