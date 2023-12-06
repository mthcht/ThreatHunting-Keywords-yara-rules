rule OSCP_Cheatsheets
{
    meta:
        description = "Detection patterns for the tool 'OSCP-Cheatsheets' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSCP-Cheatsheets"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: kerberoasting keyword. attack that allows any domain user to request kerberos tickets from TGS that are encrypted with NTLM hash of the plaintext password of a domain user account that is used as a service account (i.e account used for running an IIS service) and crack them offline avoiding AD account lockouts.
        // Reference: https://github.com/blackc03r/OSCP-Cheatsheets/blob/master/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md
        $string1 = /kerberoasting/ nocase ascii wide

    condition:
        any of them
}
