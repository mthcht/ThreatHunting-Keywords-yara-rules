rule crontab
{
    meta:
        description = "Detection patterns for the tool 'crontab' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crontab"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1 = /crontab.{0,1000}\ssleep\s.{0,1000}ncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}crontab/ nocase ascii wide

    condition:
        any of them
}
