rule echoac_poc
{
    meta:
        description = "Detection patterns for the tool 'echoac-poc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echoac-poc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string1 = /.{0,1000}\/echoac\-poc\.git.{0,1000}/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string2 = /.{0,1000}\/PoC\/PrivilegeEscalation.{0,1000}/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string3 = /.{0,1000}\\PoC\\PrivilegeEscalation.{0,1000}/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string4 = /.{0,1000}echoac\-poc\-main.{0,1000}/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string5 = /.{0,1000}kite03\/echoac\-poc.{0,1000}/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string6 = /.{0,1000}shell\sshould\snow\sbe\srunning\sas\snt\sauthority\\\\system\!.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
