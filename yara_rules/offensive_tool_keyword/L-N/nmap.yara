rule nmap
{
    meta:
        description = "Detection patterns for the tool 'nmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1 = /\sacarsd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string2 = /\saddress\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string3 = /\safp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string4 = /\safp\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string5 = /\safp\-path\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string6 = /\safp\-serverinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string7 = /\safp\-showmount\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string8 = /\sajp\-auth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string9 = /\sajp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string10 = /\sajp\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string11 = /\sajp\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string12 = /\sajp\-request\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string13 = /\sallseeingeye\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string14 = /\samqp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string15 = /\sasn\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string16 = /\sauth\-owners\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string17 = /\sauth\-spoof\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string18 = /\sbackorifice\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string19 = /\sbackorifice\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string20 = /\sbacnet\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string21 = /\sbanner\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string22 = /\sbitcoin\-getaddr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string23 = /\sbitcoin\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string24 = /\sbitcoinrpc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string25 = /\sbittorrent\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string26 = /\sbjnp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string27 = /\sbroadcast\-ataoe\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string28 = /\sbroadcast\-avahi\-dos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string29 = /\sbroadcast\-bjnp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string30 = /\sbroadcast\-db2\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string31 = /\sbroadcast\-dhcp6\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string32 = /\sbroadcast\-dhcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string33 = /\sbroadcast\-dns\-service\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string34 = /\sbroadcast\-dropbox\-listener\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string35 = /\sbroadcast\-eigrp\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string36 = /\sbroadcast\-hid\-discoveryd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string37 = /\sbroadcast\-igmp\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string38 = /\sbroadcast\-jenkins\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string39 = /\sbroadcast\-listener\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string40 = /\sbroadcast\-ms\-sql\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string41 = /\sbroadcast\-netbios\-master\-browser\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string42 = /\sbroadcast\-networker\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string43 = /\sbroadcast\-novell\-locate\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string44 = /\sbroadcast\-ospf2\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string45 = /\sbroadcast\-pc\-anywhere\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string46 = /\sbroadcast\-pc\-duo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string47 = /\sbroadcast\-pim\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string48 = /\sbroadcast\-ping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string49 = /\sbroadcast\-pppoe\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string50 = /\sbroadcast\-rip\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string51 = /\sbroadcast\-ripng\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string52 = /\sbroadcast\-sonicwall\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string53 = /\sbroadcast\-sybase\-asa\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string54 = /\sbroadcast\-tellstick\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string55 = /\sbroadcast\-upnp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string56 = /\sbroadcast\-versant\-locate\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string57 = /\sbroadcast\-wake\-on\-lan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string58 = /\sbroadcast\-wpad\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string59 = /\sbroadcast\-wsdd\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string60 = /\sbroadcast\-xdmcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string61 = /\scassandra\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string62 = /\scassandra\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string63 = /\scccam\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string64 = /\scics\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string65 = /\scics\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string66 = /\scics\-user\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string67 = /\scics\-user\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string68 = /\scitrix\-brute\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string69 = /\scitrix\-enum\-apps\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string70 = /\scitrix\-enum\-apps\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string71 = /\scitrix\-enum\-servers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string72 = /\scitrix\-enum\-servers\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string73 = /\sclamav\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string74 = /\sclock\-skew\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string75 = /\scoap\-resources\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string76 = /\scouchdb\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string77 = /\scouchdb\-stats\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string78 = /\screds\-summary\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string79 = /\scups\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string80 = /\scups\-queue\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string81 = /\scvs\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string82 = /\scvs\-brute\-repository\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string83 = /\sdaap\-get\-library\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string84 = /\sdaytime\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string85 = /\sdb2\-das\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string86 = /\sdeluge\-rpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string87 = /\sdhcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string88 = /\sdicom\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string89 = /\sdicom\-ping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string90 = /\sdict\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string91 = /\sdistcc\-cve2004\-2687\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string92 = /\sdns\-blacklist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string93 = /\sdns\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string94 = /\sdns\-cache\-snoop\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string95 = /\sdns\-check\-zone\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string96 = /\sdns\-client\-subnet\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string97 = /\sdns\-fuzz\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string98 = /\sdns\-ip6\-arpa\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string99 = /\sdnslog\-cn\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string100 = /\sdns\-nsec3\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string101 = /\sdns\-nsec\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string102 = /\sdns\-nsid\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string103 = /\sdns\-random\-srcport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string104 = /\sdns\-random\-txid\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string105 = /\sdns\-recursion\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string106 = /\sdns\-service\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string107 = /\sdns\-srv\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string108 = /\sdns\-update\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string109 = /\sdns\-zeustracker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string110 = /\sdns\-zone\-transfer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string111 = /\sdocker\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string112 = /\sdomcon\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string113 = /\sdomcon\-cmd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string114 = /\sdomino\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string115 = /\sdpap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string116 = /\sdrda\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string117 = /\sdrda\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string118 = /\sduplicates\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string119 = /\seap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string120 = /\senip\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string121 = /\sepmd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string122 = /\seppc\-enum\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string123 = /\sfcrdns\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string124 = /\sfinger\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string125 = /\sfingerprint\-strings\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string126 = /\sfirewalk\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string127 = /\sfirewall\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string128 = /\sflume\-master\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string129 = /\sfox\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string130 = /\sfreelancer\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string131 = /\sftp\-anon\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string132 = /\sftp\-bounce\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string133 = /\sftp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string134 = /\sftp\-libopie\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string135 = /\sftp\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string136 = /\sftp\-proftpd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string137 = /\sftp\-syst\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string138 = /\sftp\-vsftpd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string139 = /\sftp\-vuln\-cve2010\-4221\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string140 = /\sganglia\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string141 = /\sgiop\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string142 = /\sgkrellm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string143 = /\sgopher\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string144 = /\sgpsd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string145 = /\shadoop\-datanode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string146 = /\shadoop\-jobtracker\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string147 = /\shadoop\-namenode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string148 = /\shadoop\-secondary\-namenode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string149 = /\shadoop\-tasktracker\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string150 = /\shbase\-master\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string151 = /\shbase\-region\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string152 = /\shddtemp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string153 = /\shnap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string154 = /\shostmap\-bfk\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string155 = /\shostmap\-crtsh\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string156 = /\shostmap\-robtex\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string157 = /\shttp\-adobe\-coldfusion\-apsa1301\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string158 = /\shttp\-affiliate\-id\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string159 = /\shttp\-apache\-negotiation\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string160 = /\shttp\-apache\-server\-status\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string161 = /\shttp\-aspnet\-debug\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string162 = /\shttp\-auth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string163 = /\shttp\-auth\-finder\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string164 = /\shttp\-avaya\-ipoffice\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string165 = /\shttp\-awstatstotals\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string166 = /\shttp\-axis2\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string167 = /\shttp\-backup\-finder\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string168 = /\shttp\-barracuda\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string169 = /\shttp\-bigip\-cookie\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string170 = /\shttp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string171 = /\shttp\-cakephp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string172 = /\shttp\-chrono\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string173 = /\shttp\-cisco\-anyconnect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string174 = /\shttp\-coldfusion\-subzero\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string175 = /\shttp\-comments\-displayer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string176 = /\shttp\-config\-backup\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string177 = /\shttp\-cookie\-flags\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string178 = /\shttp\-cors\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string179 = /\shttp\-cross\-domain\-policy\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string180 = /\shttp\-csrf\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string181 = /\shttp\-date\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string182 = /\shttp\-default\-accounts\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string183 = /\shttp\-devframework\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string184 = /\shttp\-dlink\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string185 = /\shttp\-dombased\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string186 = /\shttp\-domino\-enum\-passwords\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string187 = /\shttp\-drupal\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string188 = /\shttp\-drupal\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string189 = /\shttp\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string190 = /\shttp\-errors\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string191 = /\shttp\-exif\-spider\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string192 = /\shttp\-favicon\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string193 = /\shttp\-feed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string194 = /\shttp\-fetch\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string195 = /\shttp\-fileupload\-exploiter\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string196 = /\shttp\-form\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string197 = /\shttp\-form\-fuzzer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string198 = /\shttp\-frontpage\-login\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string199 = /\shttp\-generator\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string200 = /\shttp\-git\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string201 = /\shttp\-gitweb\-projects\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string202 = /\shttp\-google\-malware\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string203 = /\shttp\-grep\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string204 = /\shttp\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string205 = /\shttp\-hp\-ilo\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string206 = /\shttp\-huawei\-hg5xx\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string207 = /\shttp\-icloud\-findmyiphone\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string208 = /\shttp\-icloud\-sendmsg\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string209 = /\shttp\-iis\-short\-name\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string210 = /\shttp\-iis\-webdav\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string211 = /\shttp\-internal\-ip\-disclosure\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string212 = /\shttp\-joomla\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string213 = /\shttp\-jsonp\-detection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string214 = /\shttp\-lexmark\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string215 = /\shttp\-lfi\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string216 = /\shttp\-litespeed\-sourcecode\-download\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string217 = /\shttp\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string218 = /\shttp\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string219 = /\shttp\-majordomo2\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string220 = /\shttp\-malware\-host\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string221 = /\shttp\-mcmp\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string222 = /\shttp\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string223 = /\shttp\-method\-tamper\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string224 = /\shttp\-mobileversion\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string225 = /\shttp\-nikto\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string226 = /\shttp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string227 = /\shttp\-open\-proxy\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string228 = /\shttp\-open\-redirect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string229 = /\shttp\-passwd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string230 = /\shttp\-phpmyadmin\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string231 = /\shttp\-phpself\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string232 = /\shttp\-php\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string233 = /\shttp\-proxy\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string234 = /\shttp\-put\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string235 = /\shttp\-qnap\-nas\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string236 = /\shttp\-referer\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string237 = /\shttp\-rfi\-spider\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string238 = /\shttp\-robots\.txt\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string239 = /\shttp\-robtex\-reverse\-ip\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string240 = /\shttp\-robtex\-shared\-ns\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string241 = /\shttp\-sap\-netweaver\-leak\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string242 = /\shttp\-security\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string243 = /\shttp\-server\-header\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string244 = /\shttp\-shellshock\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string245 = /\shttp\-sitemap\-generator\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string246 = /\shttp\-slowloris\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string247 = /\shttp\-slowloris\-check\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string248 = /\shttp\-spider\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string249 = /\shttp\-sql\-injection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string250 = /\shttps\-redirect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string251 = /\shttp\-stored\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string252 = /\shttp\-svn\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string253 = /\shttp\-svn\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string254 = /\shttp\-tenda\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string255 = /\shttp\-title\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string256 = /\shttp\-tplink\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string257 = /\shttp\-trace\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string258 = /\shttp\-traceroute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string259 = /\shttp\-trane\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string260 = /\shttp\-unsafe\-output\-escaping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string261 = /\shttp\-useragent\-tester\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string262 = /\shttp\-userdir\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string263 = /\shttp\-vhosts\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string264 = /\shttp\-virustotal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string265 = /\shttp\-vlcstreamer\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string266 = /\shttp\-vmware\-path\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string267 = /\shttp\-vuln\-cve2006\-3392\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string268 = /\shttp\-vuln\-cve2009\-3960\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string269 = /\shttp\-vuln\-cve2010\-0738\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string270 = /\shttp\-vuln\-cve2010\-2861\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string271 = /\shttp\-vuln\-cve2011\-3192\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string272 = /\shttp\-vuln\-cve2011\-3368\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string273 = /\shttp\-vuln\-cve2012\-1823\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string274 = /\shttp\-vuln\-cve2013\-0156\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string275 = /\shttp\-vuln\-cve2013\-6786\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string276 = /\shttp\-vuln\-cve2013\-7091\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string277 = /\shttp\-vuln\-cve2014\-2126\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string278 = /\shttp\-vuln\-cve2014\-2127\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string279 = /\shttp\-vuln\-cve2014\-2128\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string280 = /\shttp\-vuln\-cve2014\-2129\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string281 = /\shttp\-vuln\-cve2014\-3704\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string282 = /\shttp\-vuln\-cve2014\-8877\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string283 = /\shttp\-vuln\-cve2015\-1427\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string284 = /\shttp\-vuln\-cve2015\-1635\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string285 = /\shttp\-vuln\-cve2017\-1001000\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string286 = /\shttp\-vuln\-cve2017\-5638\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string287 = /\shttp\-vuln\-cve2017\-5689\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string288 = /\shttp\-vuln\-cve2017\-8917\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/vulnersCom/nmap-vulners
        $string289 = /\shttp\-vulners\-regex\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string290 = /\shttp\-vuln\-misfortune\-cookie\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string291 = /\shttp\-vuln\-wnr1000\-creds\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string292 = /\shttp\-waf\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string293 = /\shttp\-waf\-fingerprint\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string294 = /\shttp\-webdav\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string295 = /\shttp\-wordpress\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string296 = /\shttp\-wordpress\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string297 = /\shttp\-wordpress\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string298 = /\shttp\-xssed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string299 = /\siax2\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string300 = /\siax2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string301 = /\sicap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string302 = /\siec\-identify\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string303 = /\sike\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string304 = /\simap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string305 = /\simap\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string306 = /\simap\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string307 = /\simap\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string308 = /\simpress\-remote\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string309 = /\sinformix\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string310 = /\sinformix\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string311 = /\sinformix\-tables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string312 = /\sip\-forwarding\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string313 = /\sip\-geolocation\-geoplugin\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string314 = /\sip\-geolocation\-ipinfodb\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string315 = /\sip\-geolocation\-map\-bing\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string316 = /\sip\-geolocation\-map\-google\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string317 = /\sip\-geolocation\-map\-kml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string318 = /\sip\-geolocation\-maxmind\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string319 = /\sip\-https\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string320 = /\sipidseq\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string321 = /\sipmi\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string322 = /\sipmi\-cipher\-zero\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string323 = /\sipmi\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string324 = /\sipv6\-multicast\-mld\-list\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string325 = /\sipv6\-node\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string326 = /\sipv6\-ra\-flood\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string327 = /\sirc\-botnet\-channels\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string328 = /\sirc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string329 = /\sirc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string330 = /\sirc\-sasl\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string331 = /\sirc\-unrealircd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string332 = /\siscsi\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string333 = /\siscsi\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string334 = /\sisns\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string335 = /\sjdwp\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string336 = /\sjdwp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string337 = /\sjdwp\-inject\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string338 = /\sjdwp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string339 = /\sknx\-gateway\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string340 = /\sknx\-gateway\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string341 = /\skrb5\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string342 = /\sldap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string343 = /\sldap\-novell\-getpass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string344 = /\sldap\-rootdse\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string345 = /\sldap\-search\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string346 = /\slexmark\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string347 = /\sllmnr\-resolve\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string348 = /\slltd\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string349 = /\slu\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string350 = /\smaxdb\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string351 = /\smcafee\-epo\-agent\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string352 = /\smembase\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string353 = /\smembase\-http\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string354 = /\smemcached\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string355 = /\smetasploit\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string356 = /\smetasploit\-msgrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string357 = /\smetasploit\-xmlrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string358 = /\smikrotik\-routeros\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string359 = /\smmouse\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string360 = /\smmouse\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string361 = /\smodbus\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string362 = /\smongodb\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string363 = /\smongodb\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string364 = /\smongodb\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string365 = /\smqtt\-subscribe\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string366 = /\smrinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string367 = /\sMS15\-034\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string368 = /\smsrpc\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string369 = /\sms\-sql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string370 = /\sms\-sql\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string371 = /\sms\-sql\-dac\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string372 = /\sms\-sql\-dump\-hashes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string373 = /\sms\-sql\-empty\-password\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string374 = /\sms\-sql\-hasdbaccess\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string375 = /\sms\-sql\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string376 = /\sms\-sql\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string377 = /\sms\-sql\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string378 = /\sms\-sql\-tables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string379 = /\sms\-sql\-xp\-cmdshell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string380 = /\smtrace\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string381 = /\smurmur\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string382 = /\smysql\-audit\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string383 = /\smysql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string384 = /\smysql\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string385 = /\smysql\-dump\-hashes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string386 = /\smysql\-empty\-password\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string387 = /\smysql\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string388 = /\smysql\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string389 = /\smysql\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string390 = /\smysql\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string391 = /\smysql\-variables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string392 = /\smysql\-vuln\-cve2012\-2122\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string393 = /\snat\-pmp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string394 = /\snat\-pmp\-mapport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string395 = /\snbd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string396 = /\snbns\-interfaces\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string397 = /\snbstat\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string398 = /\sncp\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string399 = /\sncp\-serverinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string400 = /\sndmp\-fs\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string401 = /\sndmp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string402 = /\snessus\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string403 = /\snessus\-xmlrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string404 = /\snetbus\-auth\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string405 = /\snetbus\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string406 = /\snetbus\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string407 = /\snetbus\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string408 = /\snexpose\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string409 = /\snfs\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string410 = /\snfs\-showmount\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string411 = /\snfs\-statfs\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string412 = /\snje\-node\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string413 = /\snje\-pass\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string414 = /\snntp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string415 = /\snping\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string416 = /\snrpe\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string417 = /\sntp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string418 = /\sntp\-monlist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string419 = /\somp2\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string420 = /\somp2\-enum\-targets\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string421 = /\somron\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string422 = /\sopenflow\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string423 = /\sopenlookup\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string424 = /\sopenvas\-otp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string425 = /\sopenwebnet\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string426 = /\soracle\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string427 = /\soracle\-brute\-stealth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string428 = /\soracle\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string429 = /\soracle\-sid\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string430 = /\soracle\-tns\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string431 = /\sovs\-agent\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string432 = /\sp2p\-conficker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string433 = /\spath\-mtu\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string434 = /\spcanywhere\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string435 = /\spcworx\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string436 = /\spgsql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string437 = /\spjl\-info\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string438 = /\spjl\-ready\-message\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string439 = /\spop3\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string440 = /\spop3\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string441 = /\spop3\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string442 = /\sport\-states\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string443 = /\spptp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string444 = /\spuppet\-naivesigning\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string445 = /\sqconn\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string446 = /\sqscan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string447 = /\squake1\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string448 = /\squake3\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string449 = /\squake3\-master\-getservers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string450 = /\srdp\-enum\-encryption\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string451 = /\srdp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string452 = /\srdp\-vuln\-ms12\-020\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string453 = /\srealvnc\-auth\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string454 = /\sredis\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string455 = /\sredis\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string456 = /\sresolveall\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string457 = /\sreverse\-index\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string458 = /\srexec\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string459 = /\srfc868\-time\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string460 = /\sriak\-http\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string461 = /\srlogin\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string462 = /\srmi\-dumpregistry\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string463 = /\srmi\-vuln\-classloader\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string464 = /\srpcap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string465 = /\srpcap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string466 = /\srpc\-grind\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string467 = /\srpcinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string468 = /\srsa\-vuln\-roca\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string469 = /\srsync\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string470 = /\srsync\-list\-modules\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string471 = /\srtsp\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string472 = /\srtsp\-url\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string473 = /\srusers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string474 = /\ss7\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string475 = /\ssamba\-vuln\-cve\-2012\-1182\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string476 = /\s\-\-script\ssmb\-vuln\-/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string477 = /\sservicetags\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string478 = /\sshodan\-api\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string479 = /\ssip\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string480 = /\ssip\-call\-spoof\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string481 = /\ssip\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string482 = /\ssip\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string483 = /\ssip\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string484 = /\sskypev2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string485 = /\ssmb2\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string486 = /\ssmb2\-security\-mode\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string487 = /\ssmb2\-time\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string488 = /\ssmb2\-vuln\-uptime\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string489 = /\ssmb\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string490 = /\ssmb\-double\-pulsar\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string491 = /\ssmb\-enum\-domains\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string492 = /\ssmb\-enum\-groups\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string493 = /\ssmb\-enum\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string494 = /\ssmb\-enum\-services\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string495 = /\ssmb\-enum\-sessions\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string496 = /\ssmb\-enum\-shares\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string497 = /\ssmb\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string498 = /\ssmb\-flood\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string499 = /\ssmb\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string500 = /\ssmb\-mbenum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string501 = /\ssmb\-os\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string502 = /\ssmb\-print\-text\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string503 = /\ssmb\-protocols\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string504 = /\ssmb\-psexec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string505 = /\ssmb\-security\-mode\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string506 = /\ssmb\-server\-stats\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string507 = /\ssmb\-system\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string508 = /\ssmb\-vuln\-conficker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string509 = /\ssmb\-vuln\-cve2009\-3103\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string510 = /\ssmb\-vuln\-cve\-2017\-7494\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string511 = /\ssmb\-vuln\-ms06\-025\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string512 = /\ssmb\-vuln\-ms07\-029\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string513 = /\ssmb\-vuln\-ms08\-067\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string514 = /\ssmb\-vuln\-ms10\-054\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string515 = /\ssmb\-vuln\-ms10\-061\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string516 = /\ssmb\-vuln\-ms17\-010\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string517 = /\ssmb\-vuln\-regsvc\-dos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string518 = /\ssmb\-vuln\-webexec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string519 = /\ssmb\-webexec\-exploit\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string520 = /\ssmtp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string521 = /\ssmtp\-commands\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string522 = /\ssmtp\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string523 = /\ssmtp\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string524 = /\ssmtp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string525 = /\ssmtp\-open\-relay\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string526 = /\ssmtp\-strangeport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string527 = /\ssmtp\-vuln\-cve2010\-4344\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string528 = /\ssmtp\-vuln\-cve2011\-1720\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string529 = /\ssmtp\-vuln\-cve2011\-1764\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string530 = /\ssmtp\-vuln\-cve2020\-28017\-through\-28026\-21nails\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string531 = /\ssniffer\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string532 = /\ssnmp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string533 = /\ssnmp\-hh3c\-logins\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string534 = /\ssnmp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string535 = /\ssnmp\-interfaces\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string536 = /\ssnmp\-ios\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string537 = /\ssnmp\-netstat\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string538 = /\ssnmp\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string539 = /\ssnmp\-sysdescr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string540 = /\ssnmp\-win32\-services\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string541 = /\ssnmp\-win32\-shares\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string542 = /\ssnmp\-win32\-software\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string543 = /\ssnmp\-win32\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string544 = /\ssocks\-auth\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string545 = /\ssocks\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string546 = /\ssocks\-open\-proxy\.nse/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing (stealphy mode)
        // Reference: https://nmap.org/book/nse-usage.html
        $string547 = /\s\-sS\s\-p\-\s\-\-min\-rate\=.*\s\-Pn/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string548 = /\sssh2\-enum\-algos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string549 = /\sssh\-auth\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string550 = /\sssh\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string551 = /\sssh\-hostkey\.nse/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string552 = /\sssh\-log4shell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string553 = /\sssh\-publickey\-acceptance\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string554 = /\sssh\-run\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string555 = /\ssshv1\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string556 = /\sssl\-ccs\-injection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string557 = /\sssl\-cert\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string558 = /\sssl\-cert\-intaddr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string559 = /\sssl\-date\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string560 = /\sssl\-dh\-params\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string561 = /\sssl\-enum\-ciphers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string562 = /\sssl\-heartbleed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string563 = /\sssl\-known\-key\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string564 = /\sssl\-poodle\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string565 = /\ssslv2\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string566 = /\ssslv2\-drown\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string567 = /\ssstp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string568 = /\sstun\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string569 = /\sstun\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string570 = /\sstuxnet\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string571 = /\ssupermicro\-ipmi\-conf\.nse/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string572 = /\s\-sV\s\-\-script\svulners\s/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string573 = /\ssvn\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string574 = /\stargets\-asn\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string575 = /\stargets\-ipv6\-map4to6\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string576 = /\stargets\-ipv6\-multicast\-echo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string577 = /\stargets\-ipv6\-multicast\-invalid\-dst\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string578 = /\stargets\-ipv6\-multicast\-mld\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string579 = /\stargets\-ipv6\-multicast\-slaac\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string580 = /\stargets\-ipv6\-wordlist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string581 = /\stargets\-sniffer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string582 = /\stargets\-traceroute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string583 = /\stargets\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string584 = /\steamspeak2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string585 = /\stelnet\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string586 = /\stelnet\-encryption\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string587 = /\stelnet\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string588 = /\stftp\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string589 = /\stls\-alpn\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string590 = /\stls\-nextprotoneg\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string591 = /\stls\-ticketbleed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string592 = /\stn3270\-screen\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string593 = /\stor\-consensus\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string594 = /\straceroute\-geolocation\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string595 = /\stso\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string596 = /\stso\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string597 = /\subiquiti\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string598 = /\sunittest\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string599 = /\sunusual\-port\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string600 = /\supnp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string601 = /\suptime\-agent\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string602 = /\surl\-snarf\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string603 = /\sventrilo\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string604 = /\sversant\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string605 = /\svmauthd\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string606 = /\svmware\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string607 = /\svnc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string608 = /\svnc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string609 = /\svnc\-title\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string610 = /\svoldemort\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string611 = /\svtam\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string612 = /\svulners\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string613 = /\svulscan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string614 = /\svuze\-dht\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string615 = /\swdb\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string616 = /\sweblogic\-t3\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string617 = /\swhois\-domain\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string618 = /\swhois\-ip\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string619 = /\swsdd\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string620 = /\sx11\-access\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string621 = /\sxdmcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string622 = /\sxmlrpc\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string623 = /\sxmpp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string624 = /\sxmpp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string625 = /\/acarsd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string626 = /\/address\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string627 = /\/afp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string628 = /\/afp\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string629 = /\/afp\-path\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string630 = /\/afp\-serverinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string631 = /\/afp\-showmount\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string632 = /\/ajp\-auth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string633 = /\/ajp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string634 = /\/ajp\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string635 = /\/ajp\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string636 = /\/ajp\-request\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string637 = /\/allseeingeye\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string638 = /\/amqp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string639 = /\/asn\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string640 = /\/auth\-owners\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string641 = /\/auth\-spoof\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string642 = /\/backorifice\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string643 = /\/backorifice\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string644 = /\/bacnet\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string645 = /\/banner\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string646 = /\/bitcoin\-getaddr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string647 = /\/bitcoin\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string648 = /\/bitcoinrpc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string649 = /\/bittorrent\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string650 = /\/bjnp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string651 = /\/broadcast\-ataoe\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string652 = /\/broadcast\-avahi\-dos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string653 = /\/broadcast\-bjnp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string654 = /\/broadcast\-db2\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string655 = /\/broadcast\-dhcp6\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string656 = /\/broadcast\-dhcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string657 = /\/broadcast\-dns\-service\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string658 = /\/broadcast\-dropbox\-listener\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string659 = /\/broadcast\-eigrp\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string660 = /\/broadcast\-hid\-discoveryd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string661 = /\/broadcast\-igmp\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string662 = /\/broadcast\-jenkins\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string663 = /\/broadcast\-listener\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string664 = /\/broadcast\-ms\-sql\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string665 = /\/broadcast\-netbios\-master\-browser\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string666 = /\/broadcast\-networker\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string667 = /\/broadcast\-novell\-locate\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string668 = /\/broadcast\-ospf2\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string669 = /\/broadcast\-pc\-anywhere\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string670 = /\/broadcast\-pc\-duo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string671 = /\/broadcast\-pim\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string672 = /\/broadcast\-ping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string673 = /\/broadcast\-pppoe\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string674 = /\/broadcast\-rip\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string675 = /\/broadcast\-ripng\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string676 = /\/broadcast\-sonicwall\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string677 = /\/broadcast\-sybase\-asa\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string678 = /\/broadcast\-tellstick\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string679 = /\/broadcast\-upnp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string680 = /\/broadcast\-versant\-locate\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string681 = /\/broadcast\-wake\-on\-lan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string682 = /\/broadcast\-wpad\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string683 = /\/broadcast\-wsdd\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string684 = /\/broadcast\-xdmcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string685 = /\/cassandra\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string686 = /\/cassandra\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string687 = /\/cccam\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string688 = /\/cics\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string689 = /\/cics\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string690 = /\/cics\-user\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string691 = /\/cics\-user\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string692 = /\/citrix\-brute\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string693 = /\/citrix\-enum\-apps\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string694 = /\/citrix\-enum\-apps\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string695 = /\/citrix\-enum\-servers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string696 = /\/citrix\-enum\-servers\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string697 = /\/clamav\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string698 = /\/clock\-skew\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string699 = /\/coap\-resources\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string700 = /\/couchdb\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string701 = /\/couchdb\-stats\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string702 = /\/creds\-summary\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string703 = /\/cups\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string704 = /\/cups\-queue\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string705 = /\/cvs\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string706 = /\/cvs\-brute\-repository\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string707 = /\/daap\-get\-library\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string708 = /\/daytime\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string709 = /\/db2\-das\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string710 = /\/deluge\-rpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string711 = /\/dhcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string712 = /\/dicom\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string713 = /\/dicom\-ping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string714 = /\/dict\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string715 = /\/distcc\-cve2004\-2687\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string716 = /\/dns\-blacklist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string717 = /\/dns\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string718 = /\/dns\-cache\-snoop\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string719 = /\/dns\-check\-zone\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string720 = /\/dns\-client\-subnet\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string721 = /\/dns\-fuzz\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string722 = /\/dns\-ip6\-arpa\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string723 = /\/dns\-nsec3\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string724 = /\/dns\-nsec\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string725 = /\/dns\-nsid\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string726 = /\/dns\-random\-srcport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string727 = /\/dns\-random\-txid\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string728 = /\/dns\-recursion\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string729 = /\/dns\-service\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string730 = /\/dns\-srv\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string731 = /\/dns\-update\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string732 = /\/dns\-zeustracker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string733 = /\/dns\-zone\-transfer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string734 = /\/docker\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string735 = /\/domcon\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string736 = /\/domcon\-cmd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string737 = /\/domino\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string738 = /\/dpap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string739 = /\/drda\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string740 = /\/drda\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string741 = /\/duplicates\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string742 = /\/eap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string743 = /\/enip\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string744 = /\/epmd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string745 = /\/eppc\-enum\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string746 = /\/fcrdns\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string747 = /\/finger\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string748 = /\/fingerprint\-strings\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string749 = /\/firewalk\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string750 = /\/firewall\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string751 = /\/flume\-master\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string752 = /\/fox\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string753 = /\/freelancer\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string754 = /\/ftp\-anon\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string755 = /\/ftp\-bounce\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string756 = /\/ftp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string757 = /\/ftp\-libopie\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string758 = /\/ftp\-proftpd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string759 = /\/ftp\-syst\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string760 = /\/ftp\-vsftpd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string761 = /\/ftp\-vuln\-cve2010\-4221\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string762 = /\/ganglia\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string763 = /\/giop\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string764 = /\/gkrellm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string765 = /\/gopher\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string766 = /\/gpsd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string767 = /\/hadoop\-datanode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string768 = /\/hadoop\-jobtracker\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string769 = /\/hadoop\-namenode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string770 = /\/hadoop\-secondary\-namenode\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string771 = /\/hadoop\-tasktracker\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string772 = /\/hbase\-master\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string773 = /\/hbase\-region\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string774 = /\/hddtemp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string775 = /\/hnap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string776 = /\/hostmap\-bfk\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string777 = /\/hostmap\-crtsh\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string778 = /\/hostmap\-robtex\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string779 = /\/http\-adobe\-coldfusion\-apsa1301\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string780 = /\/http\-affiliate\-id\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string781 = /\/http\-apache\-negotiation\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string782 = /\/http\-apache\-server\-status\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string783 = /\/http\-aspnet\-debug\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string784 = /\/http\-auth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string785 = /\/http\-auth\-finder\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string786 = /\/http\-avaya\-ipoffice\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string787 = /\/http\-awstatstotals\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string788 = /\/http\-axis2\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string789 = /\/http\-backup\-finder\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string790 = /\/http\-barracuda\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string791 = /\/http\-bigip\-cookie\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string792 = /\/http\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string793 = /\/http\-cakephp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string794 = /\/http\-chrono\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string795 = /\/http\-cisco\-anyconnect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string796 = /\/http\-coldfusion\-subzero\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string797 = /\/http\-comments\-displayer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string798 = /\/http\-config\-backup\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string799 = /\/http\-cookie\-flags\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string800 = /\/http\-cors\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string801 = /\/http\-cross\-domain\-policy\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string802 = /\/http\-csrf\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string803 = /\/http\-date\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string804 = /\/http\-default\-accounts\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string805 = /\/http\-devframework\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string806 = /\/http\-dlink\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string807 = /\/http\-dombased\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string808 = /\/http\-domino\-enum\-passwords\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string809 = /\/http\-drupal\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string810 = /\/http\-drupal\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string811 = /\/http\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string812 = /\/http\-errors\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string813 = /\/http\-exif\-spider\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string814 = /\/http\-favicon\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string815 = /\/http\-feed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string816 = /\/http\-fetch\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string817 = /\/http\-fileupload\-exploiter\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string818 = /\/http\-form\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string819 = /\/http\-form\-fuzzer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string820 = /\/http\-frontpage\-login\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string821 = /\/http\-generator\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string822 = /\/http\-git\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string823 = /\/http\-gitweb\-projects\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string824 = /\/http\-google\-malware\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string825 = /\/http\-grep\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string826 = /\/http\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string827 = /\/http\-hp\-ilo\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string828 = /\/http\-huawei\-hg5xx\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string829 = /\/http\-icloud\-findmyiphone\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string830 = /\/http\-icloud\-sendmsg\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string831 = /\/http\-iis\-short\-name\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string832 = /\/http\-iis\-webdav\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string833 = /\/http\-internal\-ip\-disclosure\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string834 = /\/http\-joomla\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string835 = /\/http\-jsonp\-detection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string836 = /\/http\-lexmark\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string837 = /\/http\-lfi\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string838 = /\/http\-litespeed\-sourcecode\-download\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string839 = /\/http\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string840 = /\/http\-majordomo2\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string841 = /\/http\-malware\-host\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string842 = /\/http\-mcmp\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string843 = /\/http\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string844 = /\/http\-method\-tamper\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string845 = /\/http\-mobileversion\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string846 = /\/http\-nikto\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string847 = /\/http\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string848 = /\/http\-open\-proxy\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string849 = /\/http\-open\-redirect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string850 = /\/http\-passwd\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string851 = /\/http\-phpmyadmin\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string852 = /\/http\-phpself\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string853 = /\/http\-php\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string854 = /\/http\-proxy\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string855 = /\/http\-put\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string856 = /\/http\-qnap\-nas\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string857 = /\/http\-referer\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string858 = /\/http\-rfi\-spider\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string859 = /\/http\-robots\.txt\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string860 = /\/http\-robtex\-reverse\-ip\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string861 = /\/http\-robtex\-shared\-ns\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string862 = /\/http\-sap\-netweaver\-leak\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string863 = /\/http\-security\-headers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string864 = /\/http\-server\-header\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string865 = /\/http\-shellshock\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string866 = /\/http\-sitemap\-generator\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string867 = /\/http\-slowloris\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string868 = /\/http\-slowloris\-check\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string869 = /\/http\-sql\-injection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string870 = /\/https\-redirect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string871 = /\/http\-stored\-xss\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string872 = /\/http\-svn\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string873 = /\/http\-svn\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string874 = /\/http\-tenda\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string875 = /\/http\-title\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string876 = /\/http\-tplink\-dir\-traversal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string877 = /\/http\-trace\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string878 = /\/http\-traceroute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string879 = /\/http\-trane\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string880 = /\/http\-unsafe\-output\-escaping\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string881 = /\/http\-useragent\-tester\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string882 = /\/http\-userdir\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string883 = /\/http\-vhosts\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string884 = /\/http\-virustotal\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string885 = /\/http\-vlcstreamer\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string886 = /\/http\-vmware\-path\-vuln\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string887 = /\/http\-vuln\-cve2006\-3392\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string888 = /\/http\-vuln\-cve2009\-3960\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string889 = /\/http\-vuln\-cve2010\-0738\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string890 = /\/http\-vuln\-cve2010\-2861\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string891 = /\/http\-vuln\-cve2011\-3192\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string892 = /\/http\-vuln\-cve2011\-3368\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string893 = /\/http\-vuln\-cve2012\-1823\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string894 = /\/http\-vuln\-cve2013\-0156\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string895 = /\/http\-vuln\-cve2013\-6786\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string896 = /\/http\-vuln\-cve2013\-7091\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string897 = /\/http\-vuln\-cve2014\-2126\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string898 = /\/http\-vuln\-cve2014\-2127\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string899 = /\/http\-vuln\-cve2014\-2128\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string900 = /\/http\-vuln\-cve2014\-2129\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string901 = /\/http\-vuln\-cve2014\-3704\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string902 = /\/http\-vuln\-cve2014\-8877\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string903 = /\/http\-vuln\-cve2015\-1427\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string904 = /\/http\-vuln\-cve2015\-1635\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string905 = /\/http\-vuln\-cve2017\-1001000\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string906 = /\/http\-vuln\-cve2017\-5638\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string907 = /\/http\-vuln\-cve2017\-5689\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string908 = /\/http\-vuln\-cve2017\-8917\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/vulnersCom/nmap-vulners
        $string909 = /\/http\-vulners\-regex\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string910 = /\/http\-vuln\-misfortune\-cookie\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string911 = /\/http\-vuln\-wnr1000\-creds\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string912 = /\/http\-waf\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string913 = /\/http\-waf\-fingerprint\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string914 = /\/http\-webdav\-scan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string915 = /\/http\-wordpress\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string916 = /\/http\-wordpress\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string917 = /\/http\-wordpress\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string918 = /\/http\-xssed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string919 = /\/iax2\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string920 = /\/iax2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string921 = /\/icap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string922 = /\/iec\-identify\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string923 = /\/ike\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string924 = /\/imap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string925 = /\/imap\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string926 = /\/imap\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string927 = /\/impress\-remote\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string928 = /\/informix\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string929 = /\/informix\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string930 = /\/informix\-tables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string931 = /\/ip\-forwarding\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string932 = /\/ip\-geolocation\-geoplugin\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string933 = /\/ip\-geolocation\-ipinfodb\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string934 = /\/ip\-geolocation\-map\-bing\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string935 = /\/ip\-geolocation\-map\-google\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string936 = /\/ip\-geolocation\-map\-kml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string937 = /\/ip\-geolocation\-maxmind\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string938 = /\/ip\-https\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string939 = /\/ipidseq\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string940 = /\/ipmi\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string941 = /\/ipmi\-cipher\-zero\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string942 = /\/ipmi\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string943 = /\/ipv6\-multicast\-mld\-list\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string944 = /\/ipv6\-node\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string945 = /\/ipv6\-ra\-flood\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string946 = /\/irc\-botnet\-channels\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string947 = /\/irc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string948 = /\/irc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string949 = /\/irc\-sasl\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string950 = /\/irc\-unrealircd\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string951 = /\/iscsi\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string952 = /\/iscsi\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string953 = /\/isns\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string954 = /\/jdwp\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string955 = /\/jdwp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string956 = /\/jdwp\-inject\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string957 = /\/jdwp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string958 = /\/knx\-gateway\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string959 = /\/knx\-gateway\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string960 = /\/krb5\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string961 = /\/ldap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string962 = /\/ldap\-novell\-getpass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string963 = /\/ldap\-rootdse\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string964 = /\/ldap\-search\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string965 = /\/lexmark\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string966 = /\/llmnr\-resolve\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string967 = /\/lltd\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string968 = /\/lu\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string969 = /\/maxdb\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string970 = /\/mcafee\-epo\-agent\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string971 = /\/membase\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string972 = /\/membase\-http\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string973 = /\/memcached\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string974 = /\/metasploit\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string975 = /\/metasploit\-msgrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string976 = /\/metasploit\-xmlrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string977 = /\/mikrotik\-routeros\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string978 = /\/mmouse\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string979 = /\/mmouse\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string980 = /\/modbus\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string981 = /\/mongodb\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string982 = /\/mongodb\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string983 = /\/mongodb\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string984 = /\/mqtt\-subscribe\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string985 = /\/mrinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string986 = /\/MS15\-034\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string987 = /\/msrpc\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string988 = /\/ms\-sql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string989 = /\/ms\-sql\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string990 = /\/ms\-sql\-dac\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string991 = /\/ms\-sql\-dump\-hashes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string992 = /\/ms\-sql\-empty\-password\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string993 = /\/ms\-sql\-hasdbaccess\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string994 = /\/ms\-sql\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string995 = /\/ms\-sql\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string996 = /\/ms\-sql\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string997 = /\/ms\-sql\-tables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string998 = /\/ms\-sql\-xp\-cmdshell\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string999 = /\/mtrace\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1000 = /\/murmur\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1001 = /\/mysql\-audit\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1002 = /\/mysql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1003 = /\/mysql\-databases\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1004 = /\/mysql\-dump\-hashes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1005 = /\/mysql\-empty\-password\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1006 = /\/mysql\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1007 = /\/mysql\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1008 = /\/mysql\-query\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1009 = /\/mysql\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1010 = /\/mysql\-variables\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1011 = /\/mysql\-vuln\-cve2012\-2122\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1012 = /\/nat\-pmp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1013 = /\/nat\-pmp\-mapport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1014 = /\/nbd\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1015 = /\/nbns\-interfaces\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1016 = /\/nbstat\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1017 = /\/ncp\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1018 = /\/ncp\-serverinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1019 = /\/ndmp\-fs\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1020 = /\/ndmp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1021 = /\/nessus\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1022 = /\/nessus\-xmlrpc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1023 = /\/netbus\-auth\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1024 = /\/netbus\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1025 = /\/netbus\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1026 = /\/netbus\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1027 = /\/nexpose\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1028 = /\/nfs\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1029 = /\/nfs\-showmount\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1030 = /\/nfs\-statfs\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1031 = /\/nje\-node\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1032 = /\/nje\-pass\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1033 = /\/nntp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1034 = /\/nping\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1035 = /\/nrpe\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1036 = /\/ntp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1037 = /\/ntp\-monlist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1038 = /\/omp2\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1039 = /\/omp2\-enum\-targets\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1040 = /\/omron\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1041 = /\/openflow\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1042 = /\/openlookup\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1043 = /\/openvas\-otp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1044 = /\/openwebnet\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1045 = /\/oracle\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1046 = /\/oracle\-brute\-stealth\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1047 = /\/oracle\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1048 = /\/oracle\-sid\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1049 = /\/oracle\-tns\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1050 = /\/ovs\-agent\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1051 = /\/p2p\-conficker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1052 = /\/path\-mtu\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1053 = /\/pcanywhere\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1054 = /\/pcworx\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1055 = /\/pgsql\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string1056 = /\/pjl\-info\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1057 = /\/pjl\-ready\-message\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1058 = /\/pop3\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1059 = /\/pop3\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1060 = /\/pop3\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1061 = /\/port\-states\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1062 = /\/pptp\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1063 = /\/puppet\-naivesigning\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1064 = /\/qconn\-exec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1065 = /\/qscan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1066 = /\/quake1\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1067 = /\/quake3\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1068 = /\/quake3\-master\-getservers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1069 = /\/rdp\-enum\-encryption\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1070 = /\/rdp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1071 = /\/rdp\-vuln\-ms12\-020\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1072 = /\/realvnc\-auth\-bypass\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1073 = /\/redis\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1074 = /\/redis\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1075 = /\/resolveall\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1076 = /\/reverse\-index\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1077 = /\/rexec\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1078 = /\/rfc868\-time\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1079 = /\/riak\-http\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1080 = /\/rlogin\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1081 = /\/rmi\-dumpregistry\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1082 = /\/rmi\-vuln\-classloader\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1083 = /\/rpcap\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1084 = /\/rpcap\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1085 = /\/rpc\-grind\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1086 = /\/rpcinfo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1087 = /\/rsa\-vuln\-roca\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1088 = /\/rsync\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1089 = /\/rsync\-list\-modules\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1090 = /\/rtsp\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1091 = /\/rtsp\-url\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1092 = /\/rusers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1093 = /\/s7\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1094 = /\/samba\-vuln\-cve\-2012\-1182\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1095 = /\/servicetags\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1096 = /\/shodan\-api\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1097 = /\/sip\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1098 = /\/sip\-call\-spoof\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1099 = /\/sip\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1100 = /\/sip\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1101 = /\/skypev2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1102 = /\/smb2\-capabilities\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1103 = /\/smb2\-security\-mode\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1104 = /\/smb2\-time\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1105 = /\/smb2\-vuln\-uptime\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1106 = /\/smb\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1107 = /\/smb\-double\-pulsar\-backdoor\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1108 = /\/smb\-enum\-domains\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1109 = /\/smb\-enum\-groups\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1110 = /\/smb\-enum\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1111 = /\/smb\-enum\-services\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1112 = /\/smb\-enum\-sessions\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1113 = /\/smb\-enum\-shares\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1114 = /\/smb\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1115 = /\/smb\-flood\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1116 = /\/smb\-ls\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1117 = /\/smb\-mbenum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1118 = /\/smb\-os\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1119 = /\/smb\-print\-text\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1120 = /\/smb\-protocols\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1121 = /\/smb\-psexec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1122 = /\/smb\-security\-mode\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1123 = /\/smb\-server\-stats\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1124 = /\/smb\-system\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1125 = /\/smb\-vuln\-conficker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1126 = /\/smb\-vuln\-cve2009\-3103\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1127 = /\/smb\-vuln\-cve\-2017\-7494\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string1128 = /\/smb\-vuln\-cve\-2020\-0796\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1129 = /\/smb\-vuln\-ms06\-025\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1130 = /\/smb\-vuln\-ms07\-029\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1131 = /\/smb\-vuln\-ms08\-067\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1132 = /\/smb\-vuln\-ms10\-054\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1133 = /\/smb\-vuln\-ms10\-061\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1134 = /\/smb\-vuln\-ms17\-010\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1135 = /\/smb\-vuln\-regsvc\-dos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1136 = /\/smb\-vuln\-webexec\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1137 = /\/smb\-webexec\-exploit\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1138 = /\/smtp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1139 = /\/smtp\-commands\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1140 = /\/smtp\-enum\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1141 = /\/smtp\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1142 = /\/smtp\-open\-relay\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1143 = /\/smtp\-strangeport\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1144 = /\/smtp\-vuln\-cve2010\-4344\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1145 = /\/smtp\-vuln\-cve2011\-1720\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1146 = /\/smtp\-vuln\-cve2011\-1764\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string1147 = /\/smtp\-vuln\-cve2020\-28017\-through\-28026\-21nails\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1148 = /\/sniffer\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1149 = /\/snmp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1150 = /\/snmp\-hh3c\-logins\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1151 = /\/snmp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1152 = /\/snmp\-interfaces\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1153 = /\/snmp\-ios\-config\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1154 = /\/snmp\-netstat\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1155 = /\/snmp\-processes\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1156 = /\/snmp\-sysdescr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1157 = /\/snmp\-win32\-services\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1158 = /\/snmp\-win32\-shares\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1159 = /\/snmp\-win32\-software\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1160 = /\/snmp\-win32\-users\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1161 = /\/socks\-auth\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1162 = /\/socks\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1163 = /\/socks\-open\-proxy\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1164 = /\/ssh2\-enum\-algos\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1165 = /\/ssh\-auth\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1166 = /\/ssh\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1167 = /\/ssh\-hostkey\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1168 = /\/ssh\-publickey\-acceptance\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1169 = /\/ssh\-run\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1170 = /\/sshv1\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1171 = /\/ssl\-ccs\-injection\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1172 = /\/ssl\-cert\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1173 = /\/ssl\-cert\-intaddr\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1174 = /\/ssl\-date\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1175 = /\/ssl\-dh\-params\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1176 = /\/ssl\-enum\-ciphers\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1177 = /\/ssl\-heartbleed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1178 = /\/ssl\-known\-key\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1179 = /\/ssl\-poodle\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1180 = /\/sslv2\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1181 = /\/sslv2\-drown\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1182 = /\/sstp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1183 = /\/stun\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1184 = /\/stun\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1185 = /\/stuxnet\-detect\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1186 = /\/supermicro\-ipmi\-conf\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1187 = /\/svn\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1188 = /\/targets\-asn\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1189 = /\/targets\-ipv6\-map4to6\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1190 = /\/targets\-ipv6\-multicast\-echo\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1191 = /\/targets\-ipv6\-multicast\-invalid\-dst\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1192 = /\/targets\-ipv6\-multicast\-mld\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1193 = /\/targets\-ipv6\-multicast\-slaac\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1194 = /\/targets\-ipv6\-wordlist\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1195 = /\/targets\-sniffer\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1196 = /\/targets\-traceroute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1197 = /\/targets\-xml\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1198 = /\/teamspeak2\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1199 = /\/telnet\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1200 = /\/telnet\-encryption\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1201 = /\/telnet\-ntlm\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1202 = /\/tftp\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1203 = /\/tls\-alpn\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1204 = /\/tls\-nextprotoneg\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1205 = /\/tls\-ticketbleed\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1206 = /\/tn3270\-screen\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1207 = /\/tor\-consensus\-checker\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1208 = /\/traceroute\-geolocation\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1209 = /\/tso\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1210 = /\/tso\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1211 = /\/ubiquiti\-discovery\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1212 = /\/unittest\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1213 = /\/unusual\-port\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1214 = /\/upnp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1215 = /\/uptime\-agent\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1216 = /\/url\-snarf\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1217 = /\/ventrilo\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1218 = /\/versant\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1219 = /\/vmauthd\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1220 = /\/vmware\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1221 = /\/vnc\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1222 = /\/vnc\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1223 = /\/vnc\-title\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1224 = /\/voldemort\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1225 = /\/vtam\-enum\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1226 = /\/vulners\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string1227 = /\/vulscan\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1228 = /\/vuze\-dht\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1229 = /\/wdb\-version\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1230 = /\/weblogic\-t3\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1231 = /\/whois\-domain\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1232 = /\/whois\-ip\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1233 = /\/wsdd\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1234 = /\/x11\-access\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1235 = /\/xdmcp\-discover\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1236 = /\/xmlrpc\-methods\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1237 = /\/xmpp\-brute\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1238 = /\/xmpp\-info\.nse/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1239 = /krb5\-enum\-users\s/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1240 = /krb5\-enum\-users\./ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string1241 = /nmap\s.*\-\-script\s/ nocase ascii wide

    condition:
        any of them
}