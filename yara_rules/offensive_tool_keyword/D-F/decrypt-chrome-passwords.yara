rule decrypt_chrome_passwords
{
    meta:
        description = "Detection patterns for the tool 'decrypt-chrome-passwords' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "decrypt-chrome-passwords"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple program to decrypt chrome password saved on your machine.
        // Reference: https://github.com/ohyicong/decrypt-chrome-passwords
        $string1 = /\/decrypt\-chrome\-passwords/ nocase ascii wide
        // Description: A simple program to decrypt chrome password saved on your machine.
        // Reference: https://github.com/ohyicong/decrypt-chrome-passwords
        $string2 = /decrypt_chrome_password\.py/ nocase ascii wide
        // Description: A simple program to decrypt chrome password saved on your machine.
        // Reference: https://github.com/ohyicong/decrypt-chrome-passwords
        $string3 = /decrypt\-chrome\-passwords\-main/ nocase ascii wide

    condition:
        any of them
}
