rule kwetza
{
    meta:
        description = "Detection patterns for the tool 'kwetza' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kwetza"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kwetza infects an existing Android application with either custom or default payload templates to avoid detection by antivirus. Kwetza allows you to infect Android applications using the target applications default permissions or inject additional permissions to gain additional functionality.
        // Reference: https://github.com/sensepost/kwetza
        $string1 = /sensepost\/kwetza/ nocase ascii wide

    condition:
        any of them
}
