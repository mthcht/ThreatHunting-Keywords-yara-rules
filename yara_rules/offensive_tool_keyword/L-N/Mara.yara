rule Mara
{
    meta:
        description = "Detection patterns for the tool 'Mara' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mara"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mara is a userland pty/tty sniffer
        // Reference: https://github.com/io-tl/Mara/
        $string1 = /\smain\.c\s\slog\.c\sshelljack\.c\s/ nocase ascii wide
        // Description: Mara is a userland pty/tty sniffer
        // Reference: https://github.com/io-tl/Mara/
        $string2 = /\/io\-tl\/Mara/ nocase ascii wide
        // Description: Mara is a userland pty/tty sniffer
        // Reference: https://github.com/io-tl/Mara/
        $string3 = /\/Mara\.git/ nocase ascii wide
        // Description: Mara is a userland pty/tty sniffer
        // Reference: https://github.com/io-tl/Mara/
        $string4 = /\\shelljack\.c/ nocase ascii wide

    condition:
        any of them
}
