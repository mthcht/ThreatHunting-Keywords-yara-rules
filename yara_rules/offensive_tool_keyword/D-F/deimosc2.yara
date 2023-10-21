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
        $string1 = /\/collection\/screengrab/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string2 = /\/dlls\/c2\.c/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string3 = /\/gosecretsdump/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string4 = /\/resources\/selfdestruction/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string5 = /\/shellinject/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string6 = /\/webshells\/shell\.aspx/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string7 = /\/webshells\/shell\.php/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string8 = /00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string9 = /04ca7e137e1e9feead96a7df45bb67d5ab3de190/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string10 = /38ea755e162c55ef70f9506dddfd01641fc838926af9c43eda652da63c67058b/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string11 = /DeimosC2/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string12 = /lsadump\.exe/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string13 = /minidump\.exe/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string14 = /module\sinject\s/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string15 = /ntdsdump\.exe/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string16 = /samdump\.exe/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string17 = /samdump\.py/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string18 = /screengrab\.exe/ nocase ascii wide
        // Description: DeimosC2 is a Golang command and control framework for post-exploitation.
        // Reference: https://github.com/DeimosC2/DeimosC2
        $string19 = /shadowdump\./ nocase ascii wide

    condition:
        any of them
}