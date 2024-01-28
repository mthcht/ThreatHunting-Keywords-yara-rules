rule etwunhook
{
    meta:
        description = "Detection patterns for the tool 'etwunhook' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "etwunhook"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string1 = /\setwunhook\.cpp/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string2 = /\setwunhook\.exe/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string3 = /\/etwunhook\.cpp/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string4 = /\/etwunhook\.exe/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string5 = /\/etwunhook\.git/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string6 = /\\etwunhook\.cpp/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string7 = /\\etwunhook\.exe/ nocase ascii wide
        // Description: Simple ETW unhook PoC. Overwrites NtTraceEvent opcode to disable ETW at Nt-function level.
        // Reference: https://github.com/Meowmycks/etwunhook
        $string8 = /Meowmycks\/etwunhook/ nocase ascii wide

    condition:
        any of them
}
