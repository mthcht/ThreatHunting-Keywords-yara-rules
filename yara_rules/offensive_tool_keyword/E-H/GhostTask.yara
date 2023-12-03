rule GhostTask
{
    meta:
        description = "Detection patterns for the tool 'GhostTask' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostTask"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string1 = /.{0,1000}\s\-\sdelete:\sDelete\sa\sscheduled\stask\.\sRequires\srestarting\sthe\s.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string2 = /.{0,1000}\sadd\s.{0,1000}\sdemon\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string3 = /.{0,1000}\sGhostTask\.c\s.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string4 = /.{0,1000}\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}daily.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string5 = /.{0,1000}\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}logon.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string6 = /.{0,1000}\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}second.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string7 = /.{0,1000}\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}weekly.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string8 = /.{0,1000}\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}weekly.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string9 = /.{0,1000}\/GhostTask\.git.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string10 = /.{0,1000}\\GhostTask\.h.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string11 = /.{0,1000}\\GhostTask\\.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string12 = /.{0,1000}\\GhostTask\-1\.0\\.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string13 = /.{0,1000}\\GhostTask\-main.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string14 = /.{0,1000}a7ab668cab3a63df4a03cc53c46eed13fbb13bf1.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string15 = /.{0,1000}DeleteKey\(.{0,1000}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string16 = /.{0,1000}DeleteScheduleTask\(LPCSTR\scomputerName.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string17 = /.{0,1000}GhostTask\.exe.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string18 = /.{0,1000}GhostTask\-1\.0\.zip.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string19 = /.{0,1000}netero1010\/GhostTask.{0,1000}/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string20 = /.{0,1000}Successfully\sdeleted\sscheduled\stask\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
