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
        $string1 = /\s\-exec\-shellcode\s/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string2 = /\sgcat\.py\s\-/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string3 = /\/gcat\.git/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string4 = /\/gcat\.py/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string5 = /byt3bl33d3r\/gcat/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string6 = /gcat.{0,1000}implant\.py/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string7 = /gcat\.is\.the\.shit\@gmail\.com/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string8 = /\-start\-keylogger/ nocase ascii wide
        // Description: A PoC backdoor that uses Gmail as a C&C server
        // Reference: https://github.com/byt3bl33d3r/gcat
        $string9 = /\-stop\-keylogger/ nocase ascii wide

    condition:
        any of them
}
