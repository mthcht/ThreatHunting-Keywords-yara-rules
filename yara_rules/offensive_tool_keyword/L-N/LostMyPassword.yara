rule LostMyPassword
{
    meta:
        description = "Detection patterns for the tool 'LostMyPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LostMyPassword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string1 = /\\LostMyPassword\.cfg/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string2 = /\\LostMyPassword_lng\.ini/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string3 = /\\LostMyPassword32bit/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string4 = ">LostMyPassword<" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string5 = "73882b9c273a72eb49fc2854de8b37ef3012115c0e62267acb8b955a681ec312" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string6 = "745bdc69fd7d712f65419c126b3ab5524fb96a511a21fea2d2b261607b3b2c55" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string7 = "7da421d00cd50570a79a82803c170d043fa3b2253ae2f0697e103072c34d39f1" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string8 = /LostMyPassword\.exe/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string9 = /LostMyPassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string10 = /LostMyPasswordx64\.zip/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string11 = "Search your passwords as normal user" nocase ascii wide

    condition:
        any of them
}
