rule darkarmour
{
    meta:
        description = "Detection patterns for the tool 'darkarmour' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "darkarmour"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string1 = /\s\-f\s.{0,1000}\.exe\s\-\-encrypt\sxor\s\-\-jmp\s\-o\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string2 = /\/darkarmour\.git/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string3 = /avflagged\.exe/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string4 = /bats3c\/darkarmour/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string5 = /darkarmour\.py/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string6 = /darkarmour\-master/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string7 = /reflct_dll_inject\.exe/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string8 = /shellcode_dropper\.c/ nocase ascii wide

    condition:
        any of them
}
