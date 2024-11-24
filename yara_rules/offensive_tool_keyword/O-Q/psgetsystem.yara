rule psgetsystem
{
    meta:
        description = "Detection patterns for the tool 'psgetsystem' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psgetsystem"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string1 = /\spsgetsys\.ps1/ nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string2 = /\/psgetsys\.ps1/ nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string3 = /\/psgetsystem\.git/ nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string4 = /\:CreateProcessFromParent\(\(Get\-Process\s\\"lsass\\"\)\.Id/ nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string5 = /\\psgetsys\.ps1/ nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string6 = "decoder-it/psgetsystem" nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string7 = "function ImpersonateFromParentPid" nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string8 = "ImpersonateFromParentPid -ppid" nocase ascii wide
        // Description: getsystem via parent process using ps1 & embeded c#
        // Reference: https://github.com/decoder-it/psgetsystem
        $string9 = "Simple powershell/C# to spawn a process under a different parent process" nocase ascii wide

    condition:
        any of them
}
