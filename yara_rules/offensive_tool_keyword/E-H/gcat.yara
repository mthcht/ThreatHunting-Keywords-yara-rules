rule gcat
{
    meta:
        description = "Detection patterns for the tool 'gcat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gcat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string1 = /.{0,1000}\s\-exec\-shellcode\s.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string2 = /.{0,1000}\sgcat\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string3 = /.{0,1000}\/gcat\.git.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string4 = /.{0,1000}\/gcat\.py/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string5 = /.{0,1000}byt3bl33d3r\/gcat.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string6 = /.{0,1000}gcat.{0,1000}implant\.py.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string7 = /.{0,1000}gcat\.is\.the\.shit\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string8 = /.{0,1000}\-start\-keylogger.{0,1000}/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string9 = /.{0,1000}\-stop\-keylogger.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
