rule CheckSMBSigning
{
    meta:
        description = "Detection patterns for the tool 'CheckSMBSigning' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheckSMBSigning"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string1 = /\sCheckSMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string2 = /\sGet\-SMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string3 = /\/CheckSMBSigning\.git/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string4 = /\/CheckSMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string5 = /\/Get\-SMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string6 = /\\CheckSMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string7 = /\\Get\-SMBSigning\.ps1/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string8 = /\\SMBSigningNotRequired\.txt/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string9 = /2b38b8acc2d37042c0f5c2a8932f59ce8d5556103a54f2665a648476d214cc45/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string10 = /CheckSMBSigning\s\-Targets\s/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string11 = /Get\-SMBSigning\s\-DelayJitter\s/ nocase ascii wide
        // Description: Checks for SMB signing disabled on all hosts in the network
        // Reference: https://github.com/Leo4j/CheckSMBSigning
        $string12 = /Leo4j\/CheckSMBSigning/ nocase ascii wide

    condition:
        any of them
}
