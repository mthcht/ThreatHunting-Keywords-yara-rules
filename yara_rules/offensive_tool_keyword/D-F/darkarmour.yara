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
        $string1 = /.{0,1000}\s\-f\s.{0,1000}\.exe\s\-\-encrypt\sxor\s\-\-jmp\s\-o\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string2 = /.{0,1000}\/darkarmour\.git.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string3 = /.{0,1000}avflagged\.exe.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string4 = /.{0,1000}bats3c\/darkarmour.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string5 = /.{0,1000}darkarmour\.py.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string6 = /.{0,1000}darkarmour\-master.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string7 = /.{0,1000}reflct_dll_inject\.exe.{0,1000}/ nocase ascii wide
        // Description: Store and execute an encrypted windows binary from inside memorywithout a single bit touching disk.
        // Reference: https://github.com/bats3c/darkarmour
        $string8 = /.{0,1000}shellcode_dropper\.c.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
