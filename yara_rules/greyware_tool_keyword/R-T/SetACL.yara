rule SetACL
{
    meta:
        description = "Detection patterns for the tool 'SetACL' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetACL"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string1 = /\/SetACL\.exe/ nocase ascii wide
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string2 = /\/SetACL64\.\.exe/ nocase ascii wide
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string3 = /\\SetACL\.exe/ nocase ascii wide
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string4 = /\\SetACL64\.exe/ nocase ascii wide
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string5 = /\>SetACL\.exe\</ nocase ascii wide
        // Description: Manage Windows permissions from the command line
        // Reference: https://helgeklein.com/download/
        $string6 = /\>SetACL64\.\.exe\</ nocase ascii wide

    condition:
        any of them
}
