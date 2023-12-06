rule RedGuard
{
    meta:
        description = "Detection patterns for the tool 'RedGuard' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedGuard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string1 = /\.\/RedGuard/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string2 = /\/RedGuard\.git/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string3 = /\/RedGuard\.go/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string4 = /\/RedGuard_32/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string5 = /\/RedGuard_64/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string6 = /\/wikiZ\/RedGuard/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string7 = /866e5289337ab033f89bc57c5274c7ca/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string8 = /OverrideLHOST\s360\.com/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string9 = /RedGuard\.log/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string10 = /RedGuard\/core/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string11 = /RedGuard_x64\.exe/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string12 = /RedGuard_x86\.exe/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string13 = /RedGuard\s\-/ nocase ascii wide

    condition:
        any of them
}
