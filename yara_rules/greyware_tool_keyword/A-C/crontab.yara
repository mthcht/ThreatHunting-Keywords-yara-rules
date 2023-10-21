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
        $string1 = /crontab.*\ssleep\s.*ncat\s.*\s\-e\s\/bin\/bash.*crontab/ nocase ascii wide

    condition:
        any of them
}