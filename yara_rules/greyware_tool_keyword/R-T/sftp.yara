rule sftp
{
    meta:
        description = "Detection patterns for the tool 'sftp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sftp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1 = /sftp\s.*\@.*:.*\s/ nocase ascii wide

    condition:
        any of them
}