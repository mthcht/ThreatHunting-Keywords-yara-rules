rule Spring4Shell
{
    meta:
        description = "Detection patterns for the tool 'Spring4Shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spring4Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spring4Shell Proof Of Concept/Information CVE-2022-22965
        // Reference: https://github.com/BobTheShoplifter/Spring4Shell-POC
        $string1 = /\/Spring4Shell\-POC/ nocase ascii wide
        // Description: Dockerized Spring4Shell (CVE-2022-22965) PoC application and exploit
        // Reference: https://github.com/reznok/Spring4Shell-POC
        $string2 = /\/Spring4Shell\-POC/ nocase ascii wide
        // Description: CVE-2022-22965 - CVE-2010-1622 redux
        // Reference: https://github.com/DDuarte/springshell-rce-poc
        $string3 = /\/springshell\-rce\-poc/ nocase ascii wide
        // Description: Dockerized Spring4Shell (CVE-2022-22965) PoC application and exploit
        // Reference: https://github.com/reznok/Spring4Shell-POC
        $string4 = /curl\shttp.{0,1000}\/handling\-form\-submission\-complete\/rce\.jsp/ nocase ascii wide
        // Description: Dockerized Spring4Shell (CVE-2022-22965) PoC application and exploit
        // Reference: https://github.com/reznok/Spring4Shell-POC
        $string5 = /docker\srun\s\-p\s.{0,1000}\sspring4shell/ nocase ascii wide
        // Description: Spring4Shell Proof Of Concept/Information CVE-2022-22965
        // Reference: https://github.com/BobTheShoplifter/Spring4Shell-POC
        $string6 = /find\s\.\s\-name\sspring\-beans.{0,1000}\.jar/ nocase ascii wide
        // Description: Spring4Shell Proof Of Concept/Information CVE-2022-22965
        // Reference: https://github.com/TheGejr/SpringShell
        $string7 = /TheGejr\/SpringShell/ nocase ascii wide
        // Description: CVE-2022-22965 - CVE-2010-1622 redux
        // Reference: https://github.com/DDuarte/springshell-rce-poc
        $string8 = /webshell\shttp.{0,1000}\/tomcatwar\.jsp\?cmd\=/ nocase ascii wide

    condition:
        any of them
}
