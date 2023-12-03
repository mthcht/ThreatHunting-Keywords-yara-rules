rule StackCrypt
{
    meta:
        description = "Detection patterns for the tool 'StackCrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StackCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string1 = /.{0,1000}\/StackCrypt\.git.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string2 = /.{0,1000}5A6F942E\-888A\-4CE1\-A6FB\-1AB8AE22AFFA.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string3 = /.{0,1000}StackCrypt\-main.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string4 = /.{0,1000}StackEncrypt\.cpp.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string5 = /.{0,1000}StackEncrypt\.exe.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string6 = /.{0,1000}StackEncrypt\.sln.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string7 = /.{0,1000}StackEncrypt\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string8 = /.{0,1000}TheD1rkMtr\/StackCrypt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
