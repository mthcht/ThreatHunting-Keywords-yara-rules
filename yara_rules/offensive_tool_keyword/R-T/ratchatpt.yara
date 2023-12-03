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
        $string1 = /.{0,1000}\/ratchatpt\.git.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string2 = /.{0,1000}\/ratchatPT\.go.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string3 = /.{0,1000}\/ratchatPT\.syso.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string4 = /.{0,1000}\/root\/output\/ratchatPT.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string5 = /.{0,1000}\\ratchatPT\.go.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string6 = /.{0,1000}\\ratchatPT\.syso.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string7 = /.{0,1000}Agent\/ratchatPT\.go.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string8 = /.{0,1000}output\/RatChatPT_unix.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string9 = /.{0,1000}ratchatPT.{0,1000}\/bin\/bash.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string10 = /.{0,1000}RatChatPT\.exe.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string11 = /.{0,1000}RatChatPT_windows\.exe.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string12 = /.{0,1000}ratchatpt\-main.{0,1000}/ nocase ascii wide
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string13 = /.{0,1000}spartan\-conseil\/ratchatpt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
