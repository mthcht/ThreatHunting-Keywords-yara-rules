rule Radare2
{
    meta:
        description = "Detection patterns for the tool 'Radare2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radare2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: r2 is a rewrite from scratch of radare in order to provide a set of libraries and tools to work with binary files.Radare project started as a forensics tool. a scriptable command-line hexadecimal editor able to open disk files. but later added support for analyzing binaries. disassembling code. debugging programs. attaching to remote gdb servers
        // Reference: https://github.com/radareorg/radare2
        $string1 = /Radare2/ nocase ascii wide

    condition:
        any of them
}
