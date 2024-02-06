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
        $string1 = /\s\-\sdelete\:\sDelete\sa\sscheduled\stask\.\sRequires\srestarting\sthe\s/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string2 = /\sadd\s.{0,1000}\sdemon\.x64\.exe/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string3 = /\sGhostTask\.c\s/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string4 = /\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}daily/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string5 = /\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}logon/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string6 = /\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}second/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string7 = /\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}weekly/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string8 = /\.exe\slocalhost\sadd\s.{0,1000}\s\"cmd\.exe\"\s\"\/c\s.{0,1000}\"\s.{0,1000}weekly/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string9 = /\/GhostTask\.git/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string10 = /\\GhostTask\.h/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string11 = /\\GhostTask\\/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string12 = /\\GhostTask\-1\.0\\/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string13 = /\\GhostTask\-main/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string14 = /a7ab668cab3a63df4a03cc53c46eed13fbb13bf1/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string15 = /DeleteKey\(.{0,1000}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string16 = /DeleteScheduleTask\(LPCSTR\scomputerName/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string17 = /GhostTask\.exe/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string18 = /GhostTask\-1\.0\.zip/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string19 = /netero1010\/GhostTask/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string20 = /Successfully\sdeleted\sscheduled\stask\s/ nocase ascii wide

    condition:
        any of them
}
