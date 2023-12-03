rule ratchatgpt
{
    meta:
        description = "Detection patterns for the tool 'ratchatgpt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatgpt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string1 = /.{0,1000}\/output\/ratchatPT.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string2 = /.{0,1000}\/ratchatpt\.git.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string3 = /.{0,1000}\/ratchatPT\.go.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string4 = /.{0,1000}\/ratchatPT\.syso.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string5 = /.{0,1000}\\rpt_win\.exe/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string6 = /.{0,1000}RatChatPT\.exe.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string7 = /.{0,1000}RatChatPT_windows\.exe.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string8 = /.{0,1000}ratchatpt\-main.{0,1000}/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string9 = /.{0,1000}spartan\-conseil\/ratchatpt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
