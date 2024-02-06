rule NTLMSleuth
{
    meta:
        description = "Detection patterns for the tool 'NTLMSleuth' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMSleuth"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: verify NTLM hash integrity against the robust database of ntlm.pw.
        // Reference: https://github.com/jmarr73/NTLMSleuth
        $string1 = /\/NTLMSleuth\.git/ nocase ascii wide
        // Description: verify NTLM hash integrity against the robust database of ntlm.pw.
        // Reference: https://github.com/jmarr73/NTLMSleuth
        $string2 = /https\:\/\/ntlm\.pw\// nocase ascii wide
        // Description: verify NTLM hash integrity against the robust database of ntlm.pw.
        // Reference: https://github.com/jmarr73/NTLMSleuth
        $string3 = /jmarr73\/NTLMSleuth/ nocase ascii wide
        // Description: verify NTLM hash integrity against the robust database of ntlm.pw.
        // Reference: https://github.com/jmarr73/NTLMSleuth
        $string4 = /NTLMSleuth\.ps1/ nocase ascii wide
        // Description: verify NTLM hash integrity against the robust database of ntlm.pw.
        // Reference: https://github.com/jmarr73/NTLMSleuth
        $string5 = /NTLMSleuth\.sh/ nocase ascii wide

    condition:
        any of them
}
