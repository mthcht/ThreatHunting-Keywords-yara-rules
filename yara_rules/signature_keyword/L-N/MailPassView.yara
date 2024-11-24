rule MailPassView
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "signature_keyword"

    strings:
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string1 = "HackTool:Win32/Passview!MTB" nocase ascii wide

    condition:
        any of them
}
