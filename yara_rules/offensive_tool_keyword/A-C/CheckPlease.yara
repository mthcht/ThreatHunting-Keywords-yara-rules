rule CheckPlease
{
    meta:
        description = "Detection patterns for the tool 'CheckPlease' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckPlease"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: c project from checkplease checking stuffs. This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads. 
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string1 = /check_all.*\.c/ nocase ascii wide
        // Description: go script from checkplease checking stuffs. This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads. 
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string2 = /check_all.*\.go/ nocase ascii wide
        // Description: perl script from checkplease checking stuffs. This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads. 
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string3 = /check_all.*\.pl/ nocase ascii wide
        // Description: ps1 script  from checkplease checking stuffs. This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads. 
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string4 = /check_all.*\.ps1/ nocase ascii wide
        // Description: python script from checkplease checking stuffs. This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads. 
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string5 = /check_all.*\.py/ nocase ascii wide
        // Description: This repository is for defenders to harden their sandboxes and AV tools. malware researchers to discover new techniques. and red teamers to get serious about their payloads.
        // Reference: https://github.com/Arvanaghi/CheckPlease
        $string6 = /CheckPlease/ nocase ascii wide

    condition:
        any of them
}