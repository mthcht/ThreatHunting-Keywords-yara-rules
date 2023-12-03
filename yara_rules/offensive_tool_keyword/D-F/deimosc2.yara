rule deimosc2
{
    meta:
        description = "Detection patterns for the tool 'deimosc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "deimosc2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string1 = /.{0,1000}\/collection\/screengrab.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string2 = /.{0,1000}\/dlls\/c2\.c.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string3 = /.{0,1000}\/gosecretsdump.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string4 = /.{0,1000}\/resources\/selfdestruction.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string5 = /.{0,1000}\/shellinject.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string6 = /.{0,1000}\/webshells\/shell\.aspx.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string7 = /.{0,1000}\/webshells\/shell\.php.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string8 = /.{0,1000}00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string9 = /.{0,1000}04ca7e137e1e9feead96a7df45bb67d5ab3de190.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string10 = /.{0,1000}38ea755e162c55ef70f9506dddfd01641fc838926af9c43eda652da63c67058b.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string11 = /.{0,1000}DeimosC2.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string12 = /.{0,1000}lsadump\.exe.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string13 = /.{0,1000}minidump\.exe.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string14 = /.{0,1000}module\sinject\s.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string15 = /.{0,1000}ntdsdump\.exe.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string16 = /.{0,1000}samdump\.exe.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string17 = /.{0,1000}samdump\.py.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string18 = /.{0,1000}screengrab\.exe.{0,1000}/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string19 = /.{0,1000}shadowdump\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
