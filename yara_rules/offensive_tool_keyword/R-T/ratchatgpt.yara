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
        $string1 = /\/output\/ratchatPT/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string2 = /\/ratchatpt\.git/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string3 = /\/ratchatPT\.go/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string4 = /\/ratchatPT\.syso/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string5 = /\\rpt_win\.exe/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string6 = /RatChatPT\.exe/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string7 = /RatChatPT_windows\.exe/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string8 = /ratchatpt\-main/ nocase ascii wide
        // Description: ratchatpt a tool using openai api as a C2
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string9 = /spartan\-conseil\/ratchatpt/ nocase ascii wide

    condition:
        any of them
}
