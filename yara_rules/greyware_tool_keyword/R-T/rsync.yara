rule rsync
{
    meta:
        description = "Detection patterns for the tool 'rsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1 = /rsync\s\-r\s.*\s.*\@.*:/ nocase ascii wide
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string2 = /rsync\s\-r\s.*\@.*:.*\s/ nocase ascii wide

    condition:
        any of them
}