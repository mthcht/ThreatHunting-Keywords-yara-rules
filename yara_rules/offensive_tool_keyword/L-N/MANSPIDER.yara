rule MANSPIDER
{
    meta:
        description = "Detection patterns for the tool 'MANSPIDER' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MANSPIDER"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string1 = /\s\-\-dirnames\sbank\sfinanc\spayable\spayment\sreconcil\sremit\svoucher\svendor\seft\sswift\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string2 = /\s\-e\sbat\scom\svbs\sps1\spsd1\spsm1\spem\skey\srsa\spub\sreg\stxt\scfg\sconf\sconfig\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string3 = /\s\-e\spfx\sp12\spkcs12\spem\skey\scrt\scer\scsr\sjks\skeystore\skey\skeys\sder\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string4 = /\s\-e\sppk\srsa\spem\sssh\srsa/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string5 = /\s\-f\spassw\s\-e\sxlsx\scsv\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string6 = /\s\-f\spassw\suser\sadmin\saccount\snetwork\slogin\slogon\scred\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string7 = /\/\.manspider\/logs/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string8 = /\/\.manspider\/loot/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string9 = /\/MANSPIDER\.git/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string10 = /\/manspider_.{0,1000}\.log/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string11 = /\/tmp\/\.manspider/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string12 = /\\manspider_.{0,1000}\.log/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string13 = /blacklanternsecurity\/MANSPIDER/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string14 = /man_spider\.manspider\:main/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string15 = /manspider\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string16 = /manspider\s.{0,1000}\/24\s\-f\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string17 = /manspider.{0,1000}\-\-loot\-dir/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string18 = /manspider.{0,1000}\-\-sharenames/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string19 = /manspider\.py/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string20 = /manspider\.spiderling/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string21 = /MANSPIDER\-master/ nocase ascii wide

    condition:
        any of them
}
