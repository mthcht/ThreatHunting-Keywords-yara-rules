rule NTMLRecon
{
    meta:
        description = "Detection patterns for the tool 'NTMLRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTMLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string1 = /.{0,1000}\sntlmrecon.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string2 = /.{0,1000}\/NTLMRecon.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string3 = /.{0,1000}\/NTLMRecon\.git.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string4 = /.{0,1000}\/ntlmrecon\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string5 = /.{0,1000}\/ntlmutil\.py.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string6 = /.{0,1000}\/ntlmutil\.py.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string7 = /.{0,1000}\\ntlmutil\.py.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string8 = /.{0,1000}ntlmrecon\s.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string9 = /.{0,1000}ntlmrecon\.csv.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string10 = /.{0,1000}ntlmrecon:main.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string11 = /.{0,1000}ntlmrecon\-fromfile\.csv.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string12 = /.{0,1000}NTLMRecon\-master.{0,1000}/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string13 = /.{0,1000}ntlmrecon\-ranges\.csv.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string14 = /.{0,1000}puzzlepeaches\/NTLMRecon.{0,1000}/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string15 = /.{0,1000}TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw\=\=.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
