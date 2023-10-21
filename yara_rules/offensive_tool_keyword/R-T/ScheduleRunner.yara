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
        $string1 = /\.exe\s\/method:create\s\/taskname:.*\s\/trigger:.*\s\/modifier:.*\s\/program:.*\s\/argument:.*\.dll\s\/remoteserver:/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string2 = /netero1010\/ScheduleRunner/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string3 = /ScheduleRunner\.csproj/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string4 = /ScheduleRunner\.exe/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and lateral movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string5 = /ScheduleRunner\.sln/ nocase ascii wide

    condition:
        any of them
}