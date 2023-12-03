rule Fuck_Etw
{
    meta:
        description = "Detection patterns for the tool 'Fuck-Etw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fuck-Etw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string1 = /.{0,1000}\/etw\-fuck\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string2 = /.{0,1000}\/etw\-fuck\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string3 = /.{0,1000}\/Fuck\-Etw\.git.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string4 = /.{0,1000}\[\#\]\sReady\sFor\sETW\sPatch\..{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string5 = /.{0,1000}\[\+\]\sETW\sPatched.{0,1000}\sNo\sLogs\sNo\sCrime\s\!.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string6 = /.{0,1000}\[i\]\sHooked\sNtdll\sBase\sAddress\s:\s.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string7 = /.{0,1000}\[i\]\sUnhooked\sNtdll\sBase\sAddress:\s.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string8 = /.{0,1000}\\etw\-fuck\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string9 = /.{0,1000}\\etw\-fuck\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string10 = /.{0,1000}40E7714F\-460D\-4CA6\-9A5A\-FB32C6769BE4.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string11 = /.{0,1000}etw\-fuck\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string12 = /.{0,1000}Fuck\-Etw\-main.{0,1000}/ nocase ascii wide
        // Description: Bypass the Event Trace Windows(ETW) and unhook ntdll.
        // Reference: https://github.com/unkvolism/Fuck-Etw
        $string13 = /.{0,1000}unkvolism\/Fuck\-Etw.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
