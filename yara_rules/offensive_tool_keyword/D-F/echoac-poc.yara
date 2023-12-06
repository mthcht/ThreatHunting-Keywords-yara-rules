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
        $string1 = /\/echoac\-poc\.git/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string2 = /\/PoC\/PrivilegeEscalation/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string3 = /\\PoC\\PrivilegeEscalation/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string4 = /echoac\-poc\-main/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string5 = /kite03\/echoac\-poc/ nocase ascii wide
        // Description: poc stealing the Kernel's KPROCESS/EPROCESS block and writing it to a newly spawned shell to elevate its privileges to the highest possible - nt authority\system
        // Reference: https://github.com/kite03/echoac-poc
        $string6 = /shell\sshould\snow\sbe\srunning\sas\snt\sauthority\\\\system\!/ nocase ascii wide

    condition:
        any of them
}
