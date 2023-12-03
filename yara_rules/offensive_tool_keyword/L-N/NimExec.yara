rule NimExec
{
    meta:
        description = "Detection patterns for the tool 'NimExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string1 = /.{0,1000}\/NimExec\.git.{0,1000}/ nocase ascii wide
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string2 = /.{0,1000}123abcbde966780cef8d9ec24523acac.{0,1000}/ nocase ascii wide
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string3 = /.{0,1000}cmd\.exe\s\/c\s.{0,1000}echo\stest\s\>\sC:\\Users\\Public\\test\.txt.{0,1000}/ nocase ascii wide
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string4 = /.{0,1000}frkngksl\/NimExec.{0,1000}/ nocase ascii wide
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string5 = /.{0,1000}NimExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Fileless Command Execution for Lateral Movement in Nim
        // Reference: https://github.com/frkngksl/NimExec
        $string6 = /.{0,1000}NimExec\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
