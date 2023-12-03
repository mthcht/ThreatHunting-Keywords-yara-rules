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
        $string1 = /.{0,1000}\/AtlasReaper\.git.{0,1000}/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string2 = /.{0,1000}AtlasReaper\.exe.{0,1000}/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string3 = /.{0,1000}AtlasReaper\-main.{0,1000}/ nocase ascii wide
        // Description: A command-line tool for reconnaissance and targeted write operations on Confluence and Jira instances.
        // Reference: https://github.com/werdhaihai/AtlasReaper
        $string4 = /.{0,1000}werdhaihai\/AtlasReaper.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
