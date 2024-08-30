rule OperaPassView
{
    meta:
        description = "Detection patterns for the tool 'OperaPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OperaPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string1 = /\/operapassview\.zip/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string2 = /\\OperaPassView\.chm/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string3 = /\\operapassview\.zip/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string4 = /\\OperaPassView_lng\.ini/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string5 = /\>OperaPassView\</ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string6 = /8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string7 = /941e4b332bf0cbb3573b3936b114a41f1d416bb96ba13c333f6269074a8ae7f6/ nocase ascii wide
        // Description: OperaPassView is a small password recovery tool that decrypts the content of the Opera Web browser password file (wand.dat) and displays the list of all Web site passwords stored in this file
        // Reference: https://www.nirsoft.net/utils/opera_password_recovery.html
        $string8 = /OperaPassView\.exe/ nocase ascii wide

    condition:
        any of them
}
