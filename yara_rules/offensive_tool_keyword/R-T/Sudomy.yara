rule Sudomy
{
    meta:
        description = "Detection patterns for the tool 'Sudomy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sudomy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string1 = /\.\/sudomy/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string2 = /\/sudomy\.api/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string3 = /All_SubdomainTOP_Seclist\.txt/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string4 = /\-dP\s\-eP\s\-rS\s\-cF\s\-pS\s\-tO\s\-gW\s\-\-httpx\s\-\-dnsprobe\s\s\-aI\swebanalyze\s\-sS/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string5 = /processhider\.c/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string6 = /screetsec\/Sudomy/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string7 = /screetsec\/Vegile/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string8 = /sudomy\.git/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string9 = /sudomy\s\-/ nocase ascii wide

    condition:
        any of them
}
