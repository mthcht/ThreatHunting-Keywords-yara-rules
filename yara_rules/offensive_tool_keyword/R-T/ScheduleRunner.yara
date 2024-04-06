rule ScheduleRunner
{
    meta:
        description = "Detection patterns for the tool 'ScheduleRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScheduleRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string1 = /\s\/taskname\:Cleanup\s/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string2 = /\.exe\s\/method\:create\s\/taskname\:.{0,1000}\s\/trigger\:.{0,1000}\s\/modifier\:.{0,1000}\s\/program\:.{0,1000}\s\/argument\:.{0,1000}\.dll\s\/remoteserver\:/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string3 = /\[\+\]\sThe\sscheduled\stask\sis\shidden\sand\sinvisible\snow/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string4 = /FF5F7C4C\-6915\-4C53\-9DA3\-B8BE6C5F1DB9/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string5 = /netero1010\/ScheduleRunner/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string6 = /NT\sAUTHOIRTY\\SYSTEM/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string7 = /ScheduleRunner\.csproj/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string8 = /ScheduleRunner\.exe/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string9 = /ScheduleRunner\.sln/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string10 = /You\sdo\snot\shave\ssufficient\spermission\sto\shide\sthe\sscheduled\stask/ nocase ascii wide

    condition:
        any of them
}
