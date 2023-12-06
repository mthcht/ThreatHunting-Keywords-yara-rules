rule traitor
{
    meta:
        description = "Detection patterns for the tool 'traitor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "traitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string1 = /\/backdoor\/traitor\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string2 = /\/cve.{0,1000}\/exploit\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string3 = /\/exploits\/.{0,1000}\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string4 = /\/gtfobins\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string5 = /\/internal\/pipe\/pipe\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string6 = /\/payloads\/payloads\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string7 = /\/pkg\/state\/sudoers\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string8 = /\/shell\/password\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string9 = /\|base64\s\-d\s\>\s\/tmp\/traitor/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string10 = /cmd\/backdoor\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string11 = /cmd\/setuid\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string12 = /go\sget\s\-u\s.{0,1000}traitor\/cmd\/traitor/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string13 = /liamg\/traitor/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string14 = /traitor\s\-a\s/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string15 = /traitor\s\-\-any\s/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string16 = /traitor\s\-e\s/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string17 = /traitor\s\-\-exploit/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string18 = /traitor\s\-p\s/ nocase ascii wide

    condition:
        any of them
}
