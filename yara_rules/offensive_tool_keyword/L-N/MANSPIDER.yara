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
        $string1 = /.{0,1000}\s\-\-dirnames\sbank\sfinanc\spayable\spayment\sreconcil\sremit\svoucher\svendor\seft\sswift\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string2 = /.{0,1000}\s\-e\sbat\scom\svbs\sps1\spsd1\spsm1\spem\skey\srsa\spub\sreg\stxt\scfg\sconf\sconfig\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string3 = /.{0,1000}\s\-e\spfx\sp12\spkcs12\spem\skey\scrt\scer\scsr\sjks\skeystore\skey\skeys\sder\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string4 = /.{0,1000}\s\-e\sppk\srsa\spem\sssh\srsa.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string5 = /.{0,1000}\s\-f\spassw\s\-e\sxlsx\scsv\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string6 = /.{0,1000}\s\-f\spassw\suser\sadmin\saccount\snetwork\slogin\slogon\scred\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string7 = /.{0,1000}\/\.manspider\/logs.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string8 = /.{0,1000}\/\.manspider\/loot.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string9 = /.{0,1000}\/MANSPIDER\.git.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string10 = /.{0,1000}\/manspider_.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string11 = /.{0,1000}\/tmp\/\.manspider.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string12 = /.{0,1000}\\manspider_.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string13 = /.{0,1000}blacklanternsecurity\/MANSPIDER.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string14 = /.{0,1000}man_spider\.manspider:main.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string15 = /.{0,1000}manspider\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string16 = /.{0,1000}manspider\s.{0,1000}\/24\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string17 = /.{0,1000}manspider.{0,1000}\-\-loot\-dir.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string18 = /.{0,1000}manspider.{0,1000}\-\-sharenames.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string19 = /.{0,1000}manspider\.py.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string20 = /.{0,1000}manspider\.spiderling.{0,1000}/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string21 = /.{0,1000}MANSPIDER\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
