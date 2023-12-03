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
        $string1 = /.{0,1000}\s\-\-flush\-attacks.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string2 = /.{0,1000}\sinstall\swapiti3.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string3 = /.{0,1000}\s\-\-max\-attack\-time.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string4 = /.{0,1000}\s\-\-skip\-crawl.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string5 = /.{0,1000}\/bin\/wapiti.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string6 = /.{0,1000}\/data\/attacks\/.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string7 = /.{0,1000}\/wapitiCore\/.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string8 = /.{0,1000}\/wapiti\-scanner\/.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string9 = /.{0,1000}blindSQLPayloads\.txt.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string10 = /.{0,1000}busterPayloads\.txt.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string11 = /.{0,1000}downloads\/wapiti\-code.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string12 = /.{0,1000}drupal_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string13 = /.{0,1000}execPayloads\.txt.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string14 = /.{0,1000}from\swapitiCore\..{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string15 = /.{0,1000}import\swapiti.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string16 = /.{0,1000}install\swapiti.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string17 = /.{0,1000}log4shell\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string18 = /.{0,1000}mod_buster\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string19 = /.{0,1000}mod_nikto\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string20 = /.{0,1000}mod_shellshock\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string21 = /.{0,1000}mod_wp_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string22 = /.{0,1000}sql_persister\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string23 = /.{0,1000}subdomain_takeovers\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string24 = /.{0,1000}subdomain\-wordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string25 = /.{0,1000}test_crawler\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string26 = /.{0,1000}venv\swapiti3.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string27 = /.{0,1000}wapiti\s\-u.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string28 = /.{0,1000}wapiti\.git.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string29 = /.{0,1000}wapiti\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string30 = /.{0,1000}wapiti3\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string31 = /.{0,1000}wapiti3\-.{0,1000}\-any\.whl.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string32 = /.{0,1000}wapiti3\/bin.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string33 = /.{0,1000}wapiti\-getcookie.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string34 = /.{0,1000}wappalyzer\.py.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string35 = /.{0,1000}xxePayloads\.ini.{0,1000}/ nocase ascii wide
        // Description: Web vulnerability scanner written in Python3
        // Reference: https://github.com/wapiti-scanner/wapiti
        $string36 = /wapiti\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
