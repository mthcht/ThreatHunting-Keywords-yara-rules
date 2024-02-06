rule bash_keylogger
{
    meta:
        description = "Detection patterns for the tool 'bash keylogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash keylogger"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1 = /history\s\-a.{0,1000}\stail\s\-n1\s\~\/\.bash_history\s\>\s\/dev\/tcp\/.{0,1000}\// nocase ascii wide

    condition:
        any of them
}
