rule tsh
{
    meta:
        description = "Detection patterns for the tool 'tsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UNIX backdoor
        // Reference: https://github.com/creaktive/tsh
        $string1 = /\/bin\/tshd/ nocase ascii wide
        // Description: UNIX backdoor
        // Reference: https://github.com/creaktive/tsh
        $string2 = /\/tmp\/tshd/ nocase ascii wide
        // Description: UNIX backdoor
        // Reference: https://github.com/creaktive/tsh
        $string3 = /creaktive\/tsh/ nocase ascii wide
        // Description: UNIX backdoor
        // Reference: https://github.com/creaktive/tsh
        $string4 = /devine\@cr0\.net/ nocase ascii wide
        // Description: UNIX backdoor
        // Reference: https://github.com/creaktive/tsh
        $string5 = /tsh_runshell\(/ nocase ascii wide

    condition:
        any of them
}
