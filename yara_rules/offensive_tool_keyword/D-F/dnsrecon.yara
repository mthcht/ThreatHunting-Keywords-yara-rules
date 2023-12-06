rule dnsrecon
{
    meta:
        description = "Detection patterns for the tool 'dnsrecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnsrecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNSRecon is a Python port of a Ruby script that I wrote to learn the language and about DNS in early 2007. This time I wanted to learn about Python and extend the functionality of the original tool and in the process re-learn how DNS works and how could it be used in the process of a security assessment and network troubleshooting.
        // Reference: https://github.com/darkoperator/dnsrecon
        $string1 = /\s\-d\s.{0,1000}\s\-t\szonewalk/ nocase ascii wide
        // Description: DNSRecon is a Python port of a Ruby script that I wrote to learn the language and about DNS in early 2007. This time I wanted to learn about Python and extend the functionality of the original tool and in the process re-learn how DNS works and how could it be used in the process of a security assessment and network troubleshooting.
        // Reference: https://github.com/darkoperator/dnsrecon
        $string2 = /dnsrecon/ nocase ascii wide

    condition:
        any of them
}
