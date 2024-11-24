rule unset
{
    meta:
        description = "Detection patterns for the tool 'unset' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unset"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disable history logging
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string1 = /unset\sHISTFILE\s\&\&\sHISTSIZE\=0\s\&\&\srm\s\-f\s\$HISTFILE\s\&\&\sunset\sHISTFILE/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = "unset HISTFILE" nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string3 = "unset HISTFILE" nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string4 = "unset HISTFILESIZE" nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string5 = "unset HISTSIZE" nocase ascii wide

    condition:
        any of them
}
