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
        $string1 = " --dirnames bank financ payable payment reconcil remit voucher vendor eft swift " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string2 = " -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string3 = " -e pfx p12 pkcs12 pem key crt cer csr jks keystore key keys der " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string4 = " -e ppk rsa pem ssh rsa" nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string5 = " -f passw -e xlsx csv " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string6 = " -f passw user admin account network login logon cred " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string7 = /\/\.manspider\/logs/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string8 = /\/\.manspider\/loot/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string9 = /\/MANSPIDER\.git/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string10 = /\/manspider_.{0,1000}\.log/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string11 = /\/tmp\/\.manspider/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string12 = /\\manspider_.{0,1000}\.log/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string13 = "blacklanternsecurity/MANSPIDER" nocase ascii wide
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
        $string21 = "MANSPIDER-master" nocase ascii wide

    condition:
        any of them
}
