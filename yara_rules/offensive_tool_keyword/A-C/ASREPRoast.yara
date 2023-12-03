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
        $string1 = /.{0,1000}\/ASREPRoast.{0,1000}/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string2 = /.{0,1000}ASREPRoast\.ps1.{0,1000}/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string3 = /.{0,1000}crackTGS.{0,1000}/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string4 = /.{0,1000}Invoke\-ASREPRoast.{0,1000}/ nocase ascii wide
        // Description: Project that retrieves crackable hashes from KRB5 AS-REP responses for users without kerberoast preauthentication enabled. 
        // Reference: https://github.com/HarmJ0y/ASREPRoast
        $string5 = /.{0,1000}tgscrack\.go.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
