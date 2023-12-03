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
        $string1 = /.{0,1000}\/backdoor\/traitor\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string2 = /.{0,1000}\/cve.{0,1000}\/exploit\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string3 = /.{0,1000}\/exploits\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string4 = /.{0,1000}\/gtfobins\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string5 = /.{0,1000}\/internal\/pipe\/pipe\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string6 = /.{0,1000}\/payloads\/payloads\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string7 = /.{0,1000}\/pkg\/state\/sudoers\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string8 = /.{0,1000}\/shell\/password\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string9 = /.{0,1000}\|base64\s\-d\s\>\s\/tmp\/traitor.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string10 = /.{0,1000}cmd\/backdoor\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string11 = /.{0,1000}cmd\/setuid\.go.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string12 = /.{0,1000}go\sget\s\-u\s.{0,1000}traitor\/cmd\/traitor.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string13 = /.{0,1000}liamg\/traitor.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string14 = /.{0,1000}traitor\s\-a\s.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string15 = /.{0,1000}traitor\s\-\-any\s.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string16 = /.{0,1000}traitor\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string17 = /.{0,1000}traitor\s\-\-exploit.{0,1000}/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string18 = /.{0,1000}traitor\s\-p\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
