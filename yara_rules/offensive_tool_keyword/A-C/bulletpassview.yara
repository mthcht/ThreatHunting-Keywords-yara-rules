rule bulletpassview
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string1 = /BulletsPassView\.exe/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string2 = /BulletsPassView\.zip/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string3 = /BulletsPassView_setup\.exe/ nocase ascii wide
        // Description: BulletsPassView is a password recovery tool that reveals the passwords stored behind the bullets in the standard password text-box of Windows operating system and Internet Explorer Web browser. After revealing the passwords. you can easily copy them to the clipboard or save them into text/html/csv/xml file.
        // Reference: https://www.nirsoft.net/utils/bullets_password_view.html
        $string4 = /BulletsPassView_x64\.exe/ nocase ascii wide

    condition:
        any of them
}
