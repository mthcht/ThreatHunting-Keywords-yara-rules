rule mailpv
{
    meta:
        description = "Detection patterns for the tool 'mailpv' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mailpv"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details  in email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string1 = /mailpv\.exe/ nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details  in email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string2 = /mailpv\.zip/ nocase ascii wide

    condition:
        any of them
}
