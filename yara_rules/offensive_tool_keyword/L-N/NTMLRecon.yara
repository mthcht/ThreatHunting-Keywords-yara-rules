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
        $string1 = /\sntlmrecon/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string2 = /\/NTLMRecon/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string3 = /\/NTLMRecon\.git/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string4 = /\/ntlmrecon\/.{0,1000}\.py/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string5 = /\/ntlmutil\.py/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string6 = /\/ntlmutil\.py/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string7 = /\\ntlmutil\.py/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string8 = /ntlmrecon\s/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string9 = /ntlmrecon\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string10 = /ntlmrecon\:main/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string11 = /ntlmrecon\-fromfile\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string12 = /NTLMRecon\-master/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string13 = /ntlmrecon\-ranges\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string14 = /puzzlepeaches\/NTLMRecon/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string15 = /TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw\=\=/ nocase ascii wide

    condition:
        any of them
}
