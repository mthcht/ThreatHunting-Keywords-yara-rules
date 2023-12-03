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
        $string1 = /.{0,1000}\.\/RedGuard.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string2 = /.{0,1000}\/RedGuard\.git.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string3 = /.{0,1000}\/RedGuard\.go.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string4 = /.{0,1000}\/RedGuard_32/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string5 = /.{0,1000}\/RedGuard_64/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string6 = /.{0,1000}\/wikiZ\/RedGuard.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string7 = /.{0,1000}866e5289337ab033f89bc57c5274c7ca.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string8 = /.{0,1000}OverrideLHOST\s360\.com.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string9 = /.{0,1000}RedGuard\.log.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string10 = /.{0,1000}RedGuard\/core.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string11 = /.{0,1000}RedGuard_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string12 = /.{0,1000}RedGuard_x86\.exe.{0,1000}/ nocase ascii wide
        // Description: RedGuard is a C2 front flow control tool.Can avoid Blue Teams.AVs.EDRs check.
        // Reference: https://github.com/wikiZ/RedGuard
        $string13 = /RedGuard\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
