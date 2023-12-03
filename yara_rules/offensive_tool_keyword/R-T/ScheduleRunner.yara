rule ScheduleRunner
{
    meta:
        description = "Detection patterns for the tool 'ScheduleRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScheduleRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string1 = /.{0,1000}\.exe\s\/method:create\s\/taskname:.{0,1000}\s\/trigger:.{0,1000}\s\/modifier:.{0,1000}\s\/program:.{0,1000}\s\/argument:.{0,1000}\.dll\s\/remoteserver:.{0,1000}/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string2 = /.{0,1000}netero1010\/ScheduleRunner.{0,1000}/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string3 = /.{0,1000}ScheduleRunner\.csproj.{0,1000}/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string4 = /.{0,1000}ScheduleRunner\.exe.{0,1000}/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string5 = /.{0,1000}ScheduleRunner\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
