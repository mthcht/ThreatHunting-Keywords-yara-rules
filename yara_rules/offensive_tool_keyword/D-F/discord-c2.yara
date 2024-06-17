rule discord_c2
{
    meta:
        description = "Detection patterns for the tool 'discord-c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord-c2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string1 = /\/\/\sDiscord\sC2/ nocase ascii wide
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string2 = /\/\/\sWilliam\sMoody/ nocase ascii wide
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string3 = /\/discord\-c2\.git/ nocase ascii wide
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string4 = /\\discord\-c2\\/ nocase ascii wide
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string5 = /bmdyy\/discord\-c2/ nocase ascii wide
        // Description: C2 communication with discord
        // Reference: https://github.com/bmdyy/discord-c2
        $string6 = /discordgo\.New\(\"Bot\s\.\.\.\"\)/ nocase ascii wide

    condition:
        any of them
}
