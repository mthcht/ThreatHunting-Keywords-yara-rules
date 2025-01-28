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
        $string1 = /\.\/sudomy/
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string2 = /\/sudomy\.api/
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string3 = /All_SubdomainTOP_Seclist\.txt/
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string4 = "-dP -eP -rS -cF -pS -tO -gW --httpx --dnsprobe  -aI webanalyze -sS"
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string5 = /processhider\.c/
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string6 = "screetsec/Sudomy"
        // Description: Ghost In The Shell - This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process.unlimited your session in metasploit and transparent. Even when it killed. it will re-run again. There always be a procces which while run another process.So we can assume that this procces is unstopable like a Ghost in The Shell
        // Reference: https://github.com/screetsec/Vegile
        $string7 = "screetsec/Vegile"
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string8 = /sudomy\.git/
        // Description: Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting
        // Reference: https://github.com/screetsec/Sudomy
        $string9 = "sudomy -"

    condition:
        any of them
}
