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
        $string1 = /\/StackCrypt\.git/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string2 = /5A6F942E\-888A\-4CE1\-A6FB\-1AB8AE22AFFA/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string3 = /StackCrypt\-main/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string4 = /StackEncrypt\.cpp/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string5 = /StackEncrypt\.exe/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string6 = /StackEncrypt\.sln/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string7 = /StackEncrypt\.vcxproj/ nocase ascii wide
        // Description: Create a new thread that will suspend every thread and encrypt its stack then going to sleep then decrypt the stacks and resume threads
        // Reference: https://github.com/TheD1rkMtr/StackCrypt
        $string8 = /TheD1rkMtr\/StackCrypt/ nocase ascii wide

    condition:
        any of them
}
