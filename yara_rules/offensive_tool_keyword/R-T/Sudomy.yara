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
        $string1 = /.{0,1000}\.\/sudomy.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string2 = /.{0,1000}\/sudomy\.api.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string3 = /.{0,1000}All_SubdomainTOP_Seclist\.txt.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string4 = /.{0,1000}\-dP\s\-eP\s\-rS\s\-cF\s\-pS\s\-tO\s\-gW\s\-\-httpx\s\-\-dnsprobe\s\s\-aI\swebanalyze\s\-sS.{0,1000}/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string5 = /.{0,1000}processhider\.c.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string6 = /.{0,1000}screetsec\/Sudomy.{0,1000}/ nocase ascii wide
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string7 = /.{0,1000}screetsec\/Vegile.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string8 = /.{0,1000}sudomy\.git.{0,1000}/ nocase ascii wide
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string9 = /sudomy\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
