rule OshiUpload
{
    meta:
        description = "Detection patterns for the tool 'OshiUpload' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OshiUpload"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string1 = /\soshi\.at\s/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string2 = /\s\-\-socks5\-hostname\s127\.0\.0\.1\:9050/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string3 = /\/oshi_run\.pl/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string4 = /\/OshiUpload\.git/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string5 = /\[info\]\sTCP\supload\sserver\sstarted\s\(tcp\.pl\)/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string6 = /1640fb593deccf72c27363463e6001a1ced831f423b00c8687555115f9365bec/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string7 = /5ety7tpkim5me6eszuwcje7bmy25pbtrjtue7zkqqgziljwqy3rrikqd\.onion/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string8 = /ADMIN_BASICAUTH_PASSWORDHASH\s\=\sf52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string9 = /ADMIN_ROUTE\s\=\s\/SuPeRsEcReTuRl\// nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string10 = /https\:\/\/oshi\.at\// nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string11 = /hypnotoad\s\-s\swebapp\.pl\s\&\&\ssleep\s5/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string12 = /oshi\.at\/onion/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string13 = /oshiatwowvdbshka\.onion/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string14 = /OshiUpload\/app/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string15 = /OshiUpload\-master\.zip/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string16 = /reverse_proxy_tcp\.txt/ nocase ascii wide
        // Description: Ephemeral file sharing engine
        // Reference: https://github.com/somenonymous/OshiUpload
        $string17 = /somenonymous\/OshiUpload/ nocase ascii wide

    condition:
        any of them
}
