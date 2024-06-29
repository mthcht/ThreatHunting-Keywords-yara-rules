rule linikatz
{
    meta:
        description = "Detection patterns for the tool 'linikatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linikatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string1 = /\/linikatz\.git/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string2 = /\/vas\/fuzzers\/fuzz\// nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string3 = /12e9256bbb969343cc20fa9e259c0af1bf12d6c7bd0263bd7b2a60575b73cf62/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string4 = /4681186a8bcaff98f0d2513d30add67345491b95f7f743883e6ca2506ba7aaaf/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string5 = /612789c90ec1040d821a985265ea3b2f57e2c8df90b3880752dcb869e45256bc/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string6 = /66c368f799227a9b571f841057e2d5f12c862360d5f7f564da9936acd67c66a0/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string7 = /691f577714a4ae22bc22ec49edec5a15bf546a9827e8e1cf4e9e688b2ba9f72e/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string8 = /8672d46e879f704b4b41a401c1a0aae5e6365f18a798a1fbaa4b1a8e711db34b/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string9 = /9a3a44c544cd596ebf94583614035575e746f57315e20ec56a819c7152ba3fe9/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string10 = /a0101bdeeb3f99c0640c203716381ef9f6bad8e89973eaa608c801ed3f6ccace/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string11 = /a1b3d36a9cc4bc118c646ae5430a6e0fc811f2ec3614a3de9682b5c07eaade2d/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string12 = /adf6d464ce449914110607706da329993186f52f99074af1b7b1734a46dd4fcf/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string13 = /b2363d2b238f9336bb270fe96db258243668a916d7ddf94bf3a3126ed7cae508/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string14 = /b8ad30b89d6cabe30501ed963b21dcaec70b3283608682678629feae2c1b2235/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string15 = /C34208EA\-8C33\-473D\-A9B4\-53FB40347EA0/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string16 = /CiscoCXSecurity\/linikatz/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string17 = /config_steal\s\/etc\/krb5\.conf\s\/etc\/krb5\.keytab/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string18 = /e69a6f8e45f8dd8ee977b6aed73cac25537c39f6fb74cf9cc225f2af1d9e4cd7/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string19 = /ERPScan\-tockenchpoken\.zip/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string20 = /f1696fdc28bdb9e757a14b2ba9e698af8f70bb928d3c9e9fb524249f20231d08/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string21 = /f3aacbbaacceb0bdcac49d9b5e1da52d6883b7d736ca68f0a98f5a1d4838b995/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string22 = /fuzzers\/rippackets\.pl/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string23 = /linikatz\.sh/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string24 = /linikatz\.zip/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string25 = /P0rtcu11i5\!/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string26 = /unix_cached_ad_hashes\.rb/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string27 = /unix_kerberos_tickets\.rb/ nocase ascii wide
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string28 = /cbeecb2981c75b8f066b1f04f19f2095bdcf22f19d0d3f1099b83963547c00cb/ nocase ascii wide

    condition:
        any of them
}
