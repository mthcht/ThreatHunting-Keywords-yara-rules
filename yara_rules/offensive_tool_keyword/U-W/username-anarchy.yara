rule username_anarchy
{
    meta:
        description = "Detection patterns for the tool 'username-anarchy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "username-anarchy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tools for generating usernames when penetration testing. Usernames are half the password brute force problem.
        // Reference: https://github.com/urbanadventurer/username-anarchy
        $string1 = /\/username\-anarchy/ nocase ascii wide
        // Description: Tools for generating usernames when penetration testing. Usernames are half the password brute force problem.
        // Reference: https://github.com/urbanadventurer/username-anarchy
        $string2 = /username\-anarchy\s/ nocase ascii wide

    condition:
        any of them
}
