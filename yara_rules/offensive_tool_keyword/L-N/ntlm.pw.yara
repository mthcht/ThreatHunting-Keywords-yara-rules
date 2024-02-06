rule ntlm_pw
{
    meta:
        description = "Detection patterns for the tool 'ntlm.pw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlm.pw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Database of NTLM hashes
        // Reference: https://ntlm.pw
        $string1 = /https\:\/\/ntlm\.pw/ nocase ascii wide

    condition:
        any of them
}
