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
        $string1 = /.{0,1000}\s\-\-script\=http\-ntlm\-info\s\-\-script\-args\=http\-ntlm\-info\.root\=.{0,1000}/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string2 = /.{0,1000}\/ntlmscan\.git.{0,1000}/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string3 = /.{0,1000}\/ntlmscan\/.{0,1000}/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string4 = /.{0,1000}ntlmscan\.py.{0,1000}/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string5 = /.{0,1000}ntlmscan\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: scan for NTLM directories
        // Reference: https://github.com/nyxgeek/ntlmscan
        $string6 = /.{0,1000}nyxgeek\/ntlmscan.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
