rule Eggshell
{
    meta:
        description = "Detection patterns for the tool 'Eggshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eggshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EggShell is a post exploitation surveillance tool written in Python. It gives you a command line session with extra functionality between you and a target machine. EggShell gives you the power and convenience of uploading/downloading files. tab completion. taking pictures. location tracking. shell command execution. persistence. escalating privileges. password retrieval. and much more. This is project is a proof of concept. intended for use on machines you own
        // Reference: https://github.com/neoneggplant/EggShell
        $string1 = /EggShell\.py/ nocase ascii wide

    condition:
        any of them
}
