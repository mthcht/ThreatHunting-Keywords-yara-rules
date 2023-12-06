rule PPLKiller
{
    meta:
        description = "Detection patterns for the tool 'PPLKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string1 = /\.exe\s\/disableLSAProtection/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string2 = /\/PPLKiller\.git/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string3 = /\/PPLKiller\// nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string4 = /\\PPLKiller/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string5 = /\\Temp\\RTCore64\.sys/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string6 = /PPLKiller\.exe/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string7 = /PPLKiller\.sln/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string8 = /PPLKiller\.vcxproj/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string9 = /PPLKiller\-master/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string10 = /processPIDByName.{0,1000}lsass\.exe/ nocase ascii wide

    condition:
        any of them
}
