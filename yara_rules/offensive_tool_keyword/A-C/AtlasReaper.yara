rule AtlasReaper
{
    meta:
        description = "Detection patterns for the tool 'AtlasReaper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasReaper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string1 = /\/AtlasReaper\.git/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string2 = /AtlasReaper\.exe/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string3 = /AtlasReaper\-main/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string4 = /werdhaihai\/AtlasReaper/ nocase ascii wide

    condition:
        any of them
}
