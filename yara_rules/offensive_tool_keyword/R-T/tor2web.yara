rule tor2web
{
    meta:
        description = "Detection patterns for the tool 'tor2web' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor2web"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string1 = /\sinstall\stor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string2 = /\st2w\.py/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string3 = /\#\ssocksport\s\=\s9050/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string4 = /\.tor2web\s/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string5 = /\/bin\/tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string6 = /\/etc\/init\.d\/tor/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string7 = /\/etc\/init\.d\/tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string8 = /\/home\/tor2web\// nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string9 = /\/t2w\.py/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string10 = /\/Tor2web\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string11 = /\/Tor2web\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string12 = /\/tor2web\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string13 = /\/Tor2web\.git/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string14 = /\/tor2web\.js/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string15 = /\>Tor2web\sError\:\s/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string16 = /5529ff4b4c60d1cfefb02f145e149ffb166229e03aff4d8917340190753cde9e/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string17 = /87c4041617fc7010b7e20630ae48cc8c17dc84cd6fb5c330f0bc92af52baa2fa/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string18 = /a276ed1739c3380b2e918da23ddac04cc117e17e08dac219bb4f82783f9f9850/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string19 = /a6479f37d1ab80d878c949e10b1b44cd7714c87a67da40c438237af0501de51f/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string20 = /Adding\sGlobaLeaks\sPGP\skey\sto\strusted\sAPT\skeys/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string21 = /apt\sinstall\s.{0,1000}tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string22 = /apt\-get\sinstall\s.{0,1000}tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string23 = /class\sT2WRPCServer\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string24 = /dist\-packages\/tor2web\// nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string25 = /from\stor2web\simport/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string26 = /globaleaks\/Tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string27 = /href\=\"\"\/\"\"\>tor2web\<\/a\>/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string28 = /http\:\/\/tor2web\./ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string29 = /https\:\/\/tor2web\./ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string30 = /info\@tor2web\.org/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string31 = /install\-tor2web\.sh/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string32 = /lists\.tor2web\.org/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string33 = /OFTC\/tor2web\// nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string34 = /remote_get_tor_exits_list\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string35 = /spawnT2W\(/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string36 = /Start\sthe\sTor2web\sproxy/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string37 = /Starting\stor\s\(via\ssystemctl\)/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string38 = /tor2web\sstart/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string39 = /tor2web\sstop/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string40 = /tor2web\.pid/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string41 = /tor2web\.service/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string42 = /tor2web\/Tor2web/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string43 = /tor2web_notification_form/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string44 = /tor2web\-cert\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string45 = /tor2web\-default\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string46 = /tor2web\-dh\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string47 = /tor2web\-globaleaks\.conf/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string48 = /tor2web\-hidden/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string49 = /tor2web\-intermediate\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string50 = /tor2web\-key\.pem/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string51 = /tor2web\-visible/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string52 = /update\-rc\.d\stor2web\sdefaults/ nocase ascii wide
        // Description: Tor2web is an HTTP proxy software that enables access to Tor Hidden Services by mean of common web browsers
        // Reference: https://github.com/tor2web/Tor2web
        $string53 = /www\.tor2web\.org/ nocase ascii wide

    condition:
        any of them
}
