rule rsocks
{
    meta:
        description = "Detection patterns for the tool 'rsocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsocks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string1 = /\srsocks\.pool/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string2 = /\srsocks\.server/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string3 = /\.rsocks\.plist/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string4 = /\/bin\/rsocks/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string5 = /\/com\.tonyseek\.rsocks\.plist/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string6 = /\/opt\/rsocks\// nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string7 = /\/rsocks\.git/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string8 = /\/rsocks\.git/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string9 = /\/rsocks\.toml/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string10 = /\/rsocks\/releases\/download\// nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string11 = /\/rsocks_linux_amd64/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string12 = /\/rsocks_windows_386\.exe/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string13 = /\\rsocks_windows_386\.exe/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string14 = /14586f0477d31640096bf4749480b78c6a6c3afde3527bcc64e9d5f70d9e93ac/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string15 = /242194dbbdaca6aa7382e0b9f9677a2e7966bc6db8934119aa096e38a9fbf86d/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string16 = /4a97ad649c31411528694fdd8751bc6521f535f57022e6a6c0a39988df20d7b0/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string17 = /51a5737c2b51190507d47557023264299f8de0b2152e89e093e0e61f64807986/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string18 = /a539e169941f55d687ca44c90a5a90715dd23871a04a64f1712e08e758df0ec0/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string19 = /a9a87bdcf06a8b5ee41a1eec95c0f9c813a5f29ba6d8eec28b07d8331aa5eb85/ nocase ascii wide
        // Description: reverse socks5 client & server
        // Reference: https://github.com/brimstone/rsocks
        $string20 = /brimstone\/rsocks/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string21 = /easy_install\srsocks/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string22 = /import\ssocket\,\ssocks\,\slisten\,\sserve\,\swrap_ssl\,\sGreenPool/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string23 = /pip\sinstall\srsocks/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string24 = /pip\sinstall\s\-U\srsocks/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string25 = /rsocks\s\-\-config/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string26 = /rsocks\/server\.py/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string27 = /rsocks\\server\.py/ nocase ascii wide
        // Description: A SOCKS 4/5 reverse proxy server
        // Reference: https://github.com/tonyseek/rsocks
        $string28 = /tonyseek\/rsocks/ nocase ascii wide

    condition:
        any of them
}
