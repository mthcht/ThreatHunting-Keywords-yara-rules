rule canisrufus
{
    meta:
        description = "Detection patterns for the tool 'canisrufus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canisrufus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string1 = /\scanisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string2 = /\sshellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string3 = " -start-keylogger" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string4 = " -stop-keylogger" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string5 = " windows/meterpreter/reverse_tcp" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string6 = /\/canisrufus\.git/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string7 = /\/canisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string8 = /\/shellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string9 = /\\canisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string10 = /\\shellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string11 = "54cbfafed88c0b70ede4fe88d02a9de61aee9eb2017c54e7ec0b1c97d755db35" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string12 = "836d7d2ecfbe96f0be128c9b1a4cdbb8e138c502c2420e91713c8b2621aa474a" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string13 = /generate_powershell_shellcode\(/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string14 = "maldevel/canisrufus" nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string15 = "msfvenom -p " nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string16 = "'User-Agent':'CanisRufus'" nocase ascii wide

    condition:
        any of them
}
