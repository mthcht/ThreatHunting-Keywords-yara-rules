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
        $string1 = " /taskname:Cleanup " nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string2 = /\.exe\s\/method\:create\s\/taskname\:.{0,100}\s\/trigger\:.{0,100}\s\/modifier\:.{0,100}\s\/program\:.{0,100}\s\/argument\:.{0,100}\.dll\s\/remoteserver\:/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string3 = /\[\+\]\sThe\sscheduled\stask\sis\shidden\sand\sinvisible\snow/ nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string4 = "FF5F7C4C-6915-4C53-9DA3-B8BE6C5F1DB9" nocase ascii wide
        // Description: A C# tool with more flexibility to customize scheduled task for both persistence and Lateral Movement in red team operation
        // Reference: https://github.com/netero1010/ScheduleRunner
        $string5 = "netero1010/ScheduleRunner" nocase ascii wide
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
        $string10 = "You do not have sufficient permission to hide the scheduled task" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
