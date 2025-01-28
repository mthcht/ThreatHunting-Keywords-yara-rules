rule NetSess
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "signature_keyword"

    strings:
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string1 = /HackTool\.Win32\.JoeWare/ nocase ascii wide

    condition:
        any of them
}
