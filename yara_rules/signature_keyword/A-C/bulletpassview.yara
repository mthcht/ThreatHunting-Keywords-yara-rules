rule bulletpassview
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "signature_keyword"

    strings:
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string1 = /HackTool\:Win32\/Passview\!MSR/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string2 = /HTool\-PassView/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string3 = /NirPassView\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}
