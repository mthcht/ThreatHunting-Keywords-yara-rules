rule wapiti
{
    meta:
        description = "Detection patterns for the tool 'wapiti' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wapiti"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string1 = /\s\-\-flush\-attacks/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string2 = /\sinstall\swapiti3/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string3 = /\s\-\-max\-attack\-time/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string4 = /\s\-\-skip\-crawl/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string5 = /\/bin\/wapiti/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string6 = /\/data\/attacks\/.{0,1000}\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string7 = /\/wapitiCore\// nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string8 = /\/wapiti\-scanner\// nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string9 = /blindSQLPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string10 = /busterPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string11 = /downloads\/wapiti\-code/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string12 = /drupal_enum\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string13 = /execPayloads\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string14 = /from\swapitiCore\./ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string15 = /import\swapiti/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string16 = /install\swapiti/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string17 = /log4shell\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string18 = /mod_buster\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string19 = /mod_nikto\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string20 = /mod_shellshock\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string21 = /mod_wp_enum\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string22 = /sql_persister\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string23 = /subdomain_takeovers\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string24 = /subdomain\-wordlist\.txt/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string25 = /test_crawler\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string26 = /venv\swapiti3/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string27 = /wapiti\s\-u/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string28 = /wapiti\.git/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string29 = /wapiti\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string30 = /wapiti3\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string31 = /wapiti3\-.{0,1000}\-any\.whl/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string32 = /wapiti3\/bin/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string33 = /wapiti\-getcookie/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string34 = /wappalyzer\.py/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string35 = /xxePayloads\.ini/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string36 = /wapiti\s\-/ nocase ascii wide

    condition:
        any of them
}
