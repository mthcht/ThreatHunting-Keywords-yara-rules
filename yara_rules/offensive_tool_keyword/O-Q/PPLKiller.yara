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
        $string1 = /.{0,1000}\.exe\s\/disableLSAProtection.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string2 = /.{0,1000}\/PPLKiller\.git.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string3 = /.{0,1000}\/PPLKiller\/.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string4 = /.{0,1000}\\PPLKiller.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string5 = /.{0,1000}\\Temp\\RTCore64\.sys.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string6 = /.{0,1000}PPLKiller\.exe.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string7 = /.{0,1000}PPLKiller\.sln.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string8 = /.{0,1000}PPLKiller\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string9 = /.{0,1000}PPLKiller\-master.{0,1000}/ nocase ascii wide
        // Description: Tool to bypass LSA Protection (aka Protected Process Light)
        // Reference: https://github.com/RedCursorSecurityConsulting/PPLKiller
        $string10 = /.{0,1000}processPIDByName.{0,1000}lsass\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
