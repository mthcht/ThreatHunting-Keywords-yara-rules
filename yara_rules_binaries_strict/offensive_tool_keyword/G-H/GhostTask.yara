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
        $string2 = /\sadd\s.{0,100}\sdemon\.x64\.exe/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string3 = /\sGhostTask\.c\s/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string4 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}daily/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string5 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}logon/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string6 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}second/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string7 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}weekly/ nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string8 = /\.exe\slocalhost\sadd\s.{0,100}\s\\"cmd\.exe\\"\s\\"\/c\s.{0,100}\\"\s.{0,100}weekly/ nocase ascii wide
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
        $string14 = "a7ab668cab3a63df4a03cc53c46eed13fbb13bf1" nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string15 = /DeleteKey\(.{0,100}SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree\\\\/ nocase ascii wide
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
        $string19 = "netero1010/GhostTask" nocase ascii wide
        // Description: Creates scheduled tasks with a restrictive security descriptor -  making them invisible to all users. - Establishes scheduled tasks directly via the registry -  bypassing the generation of standard Windows event logs. - Provides support to modify existing scheduled tasks without generating Windows event logs. - Supports remote scheduled task creation (by using specially crafted Silver Ticket). - Supports to run in C2 with in-memory PE execution module (e.g. -  BruteRatel's memexec)
        // Reference: https://github.com/netero1010/GhostTask
        $string20 = "Successfully deleted scheduled task " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
