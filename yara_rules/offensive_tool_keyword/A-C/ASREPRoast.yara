rule ASREPRoast
{
    meta:
        description = "Detection patterns for the tool 'ASREPRoast' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASREPRoast"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string1 = /\/ASREPRoast/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string2 = /ASREPRoast\.ps1/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string3 = /crackTGS/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string4 = /Invoke\-ASREPRoast/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string5 = /tgscrack\.go/ nocase ascii wide

    condition:
        any of them
}
