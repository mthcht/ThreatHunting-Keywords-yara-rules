rule greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'greyware_tool_keyword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "greyware_tool_keyword"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string1 = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide

    condition:
        any of them
}
