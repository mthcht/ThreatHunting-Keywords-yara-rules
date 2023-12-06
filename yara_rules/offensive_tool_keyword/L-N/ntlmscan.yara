rule ntlmscan
{
    meta:
        description = "Detection patterns for the tool 'ntlmscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlmscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string1 = /\s\-\-script\=http\-ntlm\-info\s\-\-script\-args\=http\-ntlm\-info\.root\=/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string2 = /\/ntlmscan\.git/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string3 = /\/ntlmscan\// nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string4 = /ntlmscan\.py/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string5 = /ntlmscan\-master\.zip/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string6 = /nyxgeek\/ntlmscan/ nocase ascii wide

    condition:
        any of them
}
