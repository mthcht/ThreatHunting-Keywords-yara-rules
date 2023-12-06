rule ratchatpt
{
    meta:
        description = "Detection patterns for the tool 'ratchatpt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatpt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string1 = /\/ratchatpt\.git/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string2 = /\/ratchatPT\.go/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string3 = /\/ratchatPT\.syso/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string4 = /\/root\/output\/ratchatPT/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string5 = /\\ratchatPT\.go/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string6 = /\\ratchatPT\.syso/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string7 = /Agent\/ratchatPT\.go/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string8 = /output\/RatChatPT_unix/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string9 = /ratchatPT.{0,1000}\/bin\/bash/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string10 = /RatChatPT\.exe/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string11 = /RatChatPT_windows\.exe/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string12 = /ratchatpt\-main/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string13 = /spartan\-conseil\/ratchatpt/ nocase ascii wide

    condition:
        any of them
}
