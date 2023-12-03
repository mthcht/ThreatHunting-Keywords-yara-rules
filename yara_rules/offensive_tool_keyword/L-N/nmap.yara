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
        $string1 = /.{0,1000}\sacarsd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string2 = /.{0,1000}\saddress\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string3 = /.{0,1000}\safp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string4 = /.{0,1000}\safp\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string5 = /.{0,1000}\safp\-path\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string6 = /.{0,1000}\safp\-serverinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string7 = /.{0,1000}\safp\-showmount\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string8 = /.{0,1000}\sajp\-auth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string9 = /.{0,1000}\sajp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string10 = /.{0,1000}\sajp\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string11 = /.{0,1000}\sajp\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string12 = /.{0,1000}\sajp\-request\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string13 = /.{0,1000}\sallseeingeye\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string14 = /.{0,1000}\samqp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string15 = /.{0,1000}\sasn\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string16 = /.{0,1000}\sauth\-owners\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string17 = /.{0,1000}\sauth\-spoof\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string18 = /.{0,1000}\sbackorifice\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string19 = /.{0,1000}\sbackorifice\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string20 = /.{0,1000}\sbacnet\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string21 = /.{0,1000}\sbanner\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string22 = /.{0,1000}\sbitcoin\-getaddr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string23 = /.{0,1000}\sbitcoin\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string24 = /.{0,1000}\sbitcoinrpc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string25 = /.{0,1000}\sbittorrent\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string26 = /.{0,1000}\sbjnp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string27 = /.{0,1000}\sbroadcast\-ataoe\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string28 = /.{0,1000}\sbroadcast\-avahi\-dos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string29 = /.{0,1000}\sbroadcast\-bjnp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string30 = /.{0,1000}\sbroadcast\-db2\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string31 = /.{0,1000}\sbroadcast\-dhcp6\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string32 = /.{0,1000}\sbroadcast\-dhcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string33 = /.{0,1000}\sbroadcast\-dns\-service\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string34 = /.{0,1000}\sbroadcast\-dropbox\-listener\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string35 = /.{0,1000}\sbroadcast\-eigrp\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string36 = /.{0,1000}\sbroadcast\-hid\-discoveryd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string37 = /.{0,1000}\sbroadcast\-igmp\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string38 = /.{0,1000}\sbroadcast\-jenkins\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string39 = /.{0,1000}\sbroadcast\-listener\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string40 = /.{0,1000}\sbroadcast\-ms\-sql\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string41 = /.{0,1000}\sbroadcast\-netbios\-master\-browser\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string42 = /.{0,1000}\sbroadcast\-networker\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string43 = /.{0,1000}\sbroadcast\-novell\-locate\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string44 = /.{0,1000}\sbroadcast\-ospf2\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string45 = /.{0,1000}\sbroadcast\-pc\-anywhere\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string46 = /.{0,1000}\sbroadcast\-pc\-duo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string47 = /.{0,1000}\sbroadcast\-pim\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string48 = /.{0,1000}\sbroadcast\-ping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string49 = /.{0,1000}\sbroadcast\-pppoe\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string50 = /.{0,1000}\sbroadcast\-rip\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string51 = /.{0,1000}\sbroadcast\-ripng\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string52 = /.{0,1000}\sbroadcast\-sonicwall\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string53 = /.{0,1000}\sbroadcast\-sybase\-asa\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string54 = /.{0,1000}\sbroadcast\-tellstick\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string55 = /.{0,1000}\sbroadcast\-upnp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string56 = /.{0,1000}\sbroadcast\-versant\-locate\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string57 = /.{0,1000}\sbroadcast\-wake\-on\-lan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string58 = /.{0,1000}\sbroadcast\-wpad\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string59 = /.{0,1000}\sbroadcast\-wsdd\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string60 = /.{0,1000}\sbroadcast\-xdmcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string61 = /.{0,1000}\scassandra\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string62 = /.{0,1000}\scassandra\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string63 = /.{0,1000}\scccam\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string64 = /.{0,1000}\scics\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string65 = /.{0,1000}\scics\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string66 = /.{0,1000}\scics\-user\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string67 = /.{0,1000}\scics\-user\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string68 = /.{0,1000}\scitrix\-brute\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string69 = /.{0,1000}\scitrix\-enum\-apps\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string70 = /.{0,1000}\scitrix\-enum\-apps\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string71 = /.{0,1000}\scitrix\-enum\-servers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string72 = /.{0,1000}\scitrix\-enum\-servers\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string73 = /.{0,1000}\sclamav\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string74 = /.{0,1000}\sclock\-skew\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string75 = /.{0,1000}\scoap\-resources\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string76 = /.{0,1000}\scouchdb\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string77 = /.{0,1000}\scouchdb\-stats\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string78 = /.{0,1000}\screds\-summary\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string79 = /.{0,1000}\scups\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string80 = /.{0,1000}\scups\-queue\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string81 = /.{0,1000}\scvs\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string82 = /.{0,1000}\scvs\-brute\-repository\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string83 = /.{0,1000}\sdaap\-get\-library\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string84 = /.{0,1000}\sdaytime\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string85 = /.{0,1000}\sdb2\-das\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string86 = /.{0,1000}\sdeluge\-rpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string87 = /.{0,1000}\sdhcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string88 = /.{0,1000}\sdicom\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string89 = /.{0,1000}\sdicom\-ping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string90 = /.{0,1000}\sdict\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string91 = /.{0,1000}\sdistcc\-cve2004\-2687\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string92 = /.{0,1000}\sdns\-blacklist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string93 = /.{0,1000}\sdns\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string94 = /.{0,1000}\sdns\-cache\-snoop\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string95 = /.{0,1000}\sdns\-check\-zone\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string96 = /.{0,1000}\sdns\-client\-subnet\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string97 = /.{0,1000}\sdns\-fuzz\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string98 = /.{0,1000}\sdns\-ip6\-arpa\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string99 = /.{0,1000}\sdnslog\-cn\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string100 = /.{0,1000}\sdns\-nsec3\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string101 = /.{0,1000}\sdns\-nsec\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string102 = /.{0,1000}\sdns\-nsid\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string103 = /.{0,1000}\sdns\-random\-srcport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string104 = /.{0,1000}\sdns\-random\-txid\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string105 = /.{0,1000}\sdns\-recursion\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string106 = /.{0,1000}\sdns\-service\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string107 = /.{0,1000}\sdns\-srv\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string108 = /.{0,1000}\sdns\-update\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string109 = /.{0,1000}\sdns\-zeustracker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string110 = /.{0,1000}\sdns\-zone\-transfer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string111 = /.{0,1000}\sdocker\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string112 = /.{0,1000}\sdomcon\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string113 = /.{0,1000}\sdomcon\-cmd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string114 = /.{0,1000}\sdomino\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string115 = /.{0,1000}\sdpap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string116 = /.{0,1000}\sdrda\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string117 = /.{0,1000}\sdrda\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string118 = /.{0,1000}\sduplicates\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string119 = /.{0,1000}\seap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string120 = /.{0,1000}\senip\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string121 = /.{0,1000}\sepmd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string122 = /.{0,1000}\seppc\-enum\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string123 = /.{0,1000}\sfcrdns\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string124 = /.{0,1000}\sfinger\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string125 = /.{0,1000}\sfingerprint\-strings\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string126 = /.{0,1000}\sfirewalk\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string127 = /.{0,1000}\sfirewall\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string128 = /.{0,1000}\sflume\-master\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string129 = /.{0,1000}\sfox\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string130 = /.{0,1000}\sfreelancer\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string131 = /.{0,1000}\sftp\-anon\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string132 = /.{0,1000}\sftp\-bounce\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string133 = /.{0,1000}\sftp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string134 = /.{0,1000}\sftp\-libopie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string135 = /.{0,1000}\sftp\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string136 = /.{0,1000}\sftp\-proftpd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string137 = /.{0,1000}\sftp\-syst\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string138 = /.{0,1000}\sftp\-vsftpd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string139 = /.{0,1000}\sftp\-vuln\-cve2010\-4221\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string140 = /.{0,1000}\sganglia\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string141 = /.{0,1000}\sgiop\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string142 = /.{0,1000}\sgkrellm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string143 = /.{0,1000}\sgopher\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string144 = /.{0,1000}\sgpsd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string145 = /.{0,1000}\shadoop\-datanode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string146 = /.{0,1000}\shadoop\-jobtracker\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string147 = /.{0,1000}\shadoop\-namenode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string148 = /.{0,1000}\shadoop\-secondary\-namenode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string149 = /.{0,1000}\shadoop\-tasktracker\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string150 = /.{0,1000}\shbase\-master\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string151 = /.{0,1000}\shbase\-region\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string152 = /.{0,1000}\shddtemp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string153 = /.{0,1000}\shnap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string154 = /.{0,1000}\shostmap\-bfk\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string155 = /.{0,1000}\shostmap\-crtsh\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string156 = /.{0,1000}\shostmap\-robtex\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string157 = /.{0,1000}\shttp\-adobe\-coldfusion\-apsa1301\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string158 = /.{0,1000}\shttp\-affiliate\-id\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string159 = /.{0,1000}\shttp\-apache\-negotiation\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string160 = /.{0,1000}\shttp\-apache\-server\-status\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string161 = /.{0,1000}\shttp\-aspnet\-debug\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string162 = /.{0,1000}\shttp\-auth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string163 = /.{0,1000}\shttp\-auth\-finder\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string164 = /.{0,1000}\shttp\-avaya\-ipoffice\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string165 = /.{0,1000}\shttp\-awstatstotals\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string166 = /.{0,1000}\shttp\-axis2\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string167 = /.{0,1000}\shttp\-backup\-finder\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string168 = /.{0,1000}\shttp\-barracuda\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string169 = /.{0,1000}\shttp\-bigip\-cookie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string170 = /.{0,1000}\shttp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string171 = /.{0,1000}\shttp\-cakephp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string172 = /.{0,1000}\shttp\-chrono\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string173 = /.{0,1000}\shttp\-cisco\-anyconnect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string174 = /.{0,1000}\shttp\-coldfusion\-subzero\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string175 = /.{0,1000}\shttp\-comments\-displayer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string176 = /.{0,1000}\shttp\-config\-backup\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string177 = /.{0,1000}\shttp\-cookie\-flags\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string178 = /.{0,1000}\shttp\-cors\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string179 = /.{0,1000}\shttp\-cross\-domain\-policy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string180 = /.{0,1000}\shttp\-csrf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string181 = /.{0,1000}\shttp\-date\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string182 = /.{0,1000}\shttp\-default\-accounts\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string183 = /.{0,1000}\shttp\-devframework\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string184 = /.{0,1000}\shttp\-dlink\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string185 = /.{0,1000}\shttp\-dombased\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string186 = /.{0,1000}\shttp\-domino\-enum\-passwords\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string187 = /.{0,1000}\shttp\-drupal\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string188 = /.{0,1000}\shttp\-drupal\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string189 = /.{0,1000}\shttp\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string190 = /.{0,1000}\shttp\-errors\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string191 = /.{0,1000}\shttp\-exif\-spider\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string192 = /.{0,1000}\shttp\-favicon\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string193 = /.{0,1000}\shttp\-feed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string194 = /.{0,1000}\shttp\-fetch\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string195 = /.{0,1000}\shttp\-fileupload\-exploiter\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string196 = /.{0,1000}\shttp\-form\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string197 = /.{0,1000}\shttp\-form\-fuzzer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string198 = /.{0,1000}\shttp\-frontpage\-login\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string199 = /.{0,1000}\shttp\-generator\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string200 = /.{0,1000}\shttp\-git\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string201 = /.{0,1000}\shttp\-gitweb\-projects\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string202 = /.{0,1000}\shttp\-google\-malware\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string203 = /.{0,1000}\shttp\-grep\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string204 = /.{0,1000}\shttp\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string205 = /.{0,1000}\shttp\-hp\-ilo\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string206 = /.{0,1000}\shttp\-huawei\-hg5xx\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string207 = /.{0,1000}\shttp\-icloud\-findmyiphone\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string208 = /.{0,1000}\shttp\-icloud\-sendmsg\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string209 = /.{0,1000}\shttp\-iis\-short\-name\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string210 = /.{0,1000}\shttp\-iis\-webdav\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string211 = /.{0,1000}\shttp\-internal\-ip\-disclosure\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string212 = /.{0,1000}\shttp\-joomla\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string213 = /.{0,1000}\shttp\-jsonp\-detection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string214 = /.{0,1000}\shttp\-lexmark\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string215 = /.{0,1000}\shttp\-lfi\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string216 = /.{0,1000}\shttp\-litespeed\-sourcecode\-download\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string217 = /.{0,1000}\shttp\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string218 = /.{0,1000}\shttp\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string219 = /.{0,1000}\shttp\-majordomo2\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string220 = /.{0,1000}\shttp\-malware\-host\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string221 = /.{0,1000}\shttp\-mcmp\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string222 = /.{0,1000}\shttp\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string223 = /.{0,1000}\shttp\-method\-tamper\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string224 = /.{0,1000}\shttp\-mobileversion\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string225 = /.{0,1000}\shttp\-nikto\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string226 = /.{0,1000}\shttp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string227 = /.{0,1000}\shttp\-open\-proxy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string228 = /.{0,1000}\shttp\-open\-redirect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string229 = /.{0,1000}\shttp\-passwd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string230 = /.{0,1000}\shttp\-phpmyadmin\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string231 = /.{0,1000}\shttp\-phpself\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string232 = /.{0,1000}\shttp\-php\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string233 = /.{0,1000}\shttp\-proxy\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string234 = /.{0,1000}\shttp\-put\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string235 = /.{0,1000}\shttp\-qnap\-nas\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string236 = /.{0,1000}\shttp\-referer\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string237 = /.{0,1000}\shttp\-rfi\-spider\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string238 = /.{0,1000}\shttp\-robots\.txt\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string239 = /.{0,1000}\shttp\-robtex\-reverse\-ip\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string240 = /.{0,1000}\shttp\-robtex\-shared\-ns\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string241 = /.{0,1000}\shttp\-sap\-netweaver\-leak\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string242 = /.{0,1000}\shttp\-security\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string243 = /.{0,1000}\shttp\-server\-header\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string244 = /.{0,1000}\shttp\-shellshock\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string245 = /.{0,1000}\shttp\-sitemap\-generator\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string246 = /.{0,1000}\shttp\-slowloris\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string247 = /.{0,1000}\shttp\-slowloris\-check\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string248 = /.{0,1000}\shttp\-spider\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string249 = /.{0,1000}\shttp\-sql\-injection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string250 = /.{0,1000}\shttps\-redirect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string251 = /.{0,1000}\shttp\-stored\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string252 = /.{0,1000}\shttp\-svn\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string253 = /.{0,1000}\shttp\-svn\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string254 = /.{0,1000}\shttp\-tenda\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string255 = /.{0,1000}\shttp\-title\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string256 = /.{0,1000}\shttp\-tplink\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string257 = /.{0,1000}\shttp\-trace\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string258 = /.{0,1000}\shttp\-traceroute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string259 = /.{0,1000}\shttp\-trane\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string260 = /.{0,1000}\shttp\-unsafe\-output\-escaping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string261 = /.{0,1000}\shttp\-useragent\-tester\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string262 = /.{0,1000}\shttp\-userdir\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string263 = /.{0,1000}\shttp\-vhosts\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string264 = /.{0,1000}\shttp\-virustotal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string265 = /.{0,1000}\shttp\-vlcstreamer\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string266 = /.{0,1000}\shttp\-vmware\-path\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string267 = /.{0,1000}\shttp\-vuln\-cve2006\-3392\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string268 = /.{0,1000}\shttp\-vuln\-cve2009\-3960\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string269 = /.{0,1000}\shttp\-vuln\-cve2010\-0738\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string270 = /.{0,1000}\shttp\-vuln\-cve2010\-2861\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string271 = /.{0,1000}\shttp\-vuln\-cve2011\-3192\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string272 = /.{0,1000}\shttp\-vuln\-cve2011\-3368\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string273 = /.{0,1000}\shttp\-vuln\-cve2012\-1823\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string274 = /.{0,1000}\shttp\-vuln\-cve2013\-0156\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string275 = /.{0,1000}\shttp\-vuln\-cve2013\-6786\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string276 = /.{0,1000}\shttp\-vuln\-cve2013\-7091\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string277 = /.{0,1000}\shttp\-vuln\-cve2014\-2126\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string278 = /.{0,1000}\shttp\-vuln\-cve2014\-2127\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string279 = /.{0,1000}\shttp\-vuln\-cve2014\-2128\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string280 = /.{0,1000}\shttp\-vuln\-cve2014\-2129\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string281 = /.{0,1000}\shttp\-vuln\-cve2014\-3704\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string282 = /.{0,1000}\shttp\-vuln\-cve2014\-8877\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string283 = /.{0,1000}\shttp\-vuln\-cve2015\-1427\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string284 = /.{0,1000}\shttp\-vuln\-cve2015\-1635\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string285 = /.{0,1000}\shttp\-vuln\-cve2017\-1001000\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string286 = /.{0,1000}\shttp\-vuln\-cve2017\-5638\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string287 = /.{0,1000}\shttp\-vuln\-cve2017\-5689\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string288 = /.{0,1000}\shttp\-vuln\-cve2017\-8917\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/vulnersCom/nmap-vulners
        $string289 = /.{0,1000}\shttp\-vulners\-regex\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string290 = /.{0,1000}\shttp\-vuln\-misfortune\-cookie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string291 = /.{0,1000}\shttp\-vuln\-wnr1000\-creds\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string292 = /.{0,1000}\shttp\-waf\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string293 = /.{0,1000}\shttp\-waf\-fingerprint\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string294 = /.{0,1000}\shttp\-webdav\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string295 = /.{0,1000}\shttp\-wordpress\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string296 = /.{0,1000}\shttp\-wordpress\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string297 = /.{0,1000}\shttp\-wordpress\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string298 = /.{0,1000}\shttp\-xssed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string299 = /.{0,1000}\siax2\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string300 = /.{0,1000}\siax2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string301 = /.{0,1000}\sicap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string302 = /.{0,1000}\siec\-identify\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string303 = /.{0,1000}\sike\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string304 = /.{0,1000}\simap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string305 = /.{0,1000}\simap\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string306 = /.{0,1000}\simap\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string307 = /.{0,1000}\simap\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string308 = /.{0,1000}\simpress\-remote\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string309 = /.{0,1000}\sinformix\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string310 = /.{0,1000}\sinformix\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string311 = /.{0,1000}\sinformix\-tables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string312 = /.{0,1000}\sip\-forwarding\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string313 = /.{0,1000}\sip\-geolocation\-geoplugin\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string314 = /.{0,1000}\sip\-geolocation\-ipinfodb\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string315 = /.{0,1000}\sip\-geolocation\-map\-bing\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string316 = /.{0,1000}\sip\-geolocation\-map\-google\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string317 = /.{0,1000}\sip\-geolocation\-map\-kml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string318 = /.{0,1000}\sip\-geolocation\-maxmind\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string319 = /.{0,1000}\sip\-https\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string320 = /.{0,1000}\sipidseq\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string321 = /.{0,1000}\sipmi\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string322 = /.{0,1000}\sipmi\-cipher\-zero\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string323 = /.{0,1000}\sipmi\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string324 = /.{0,1000}\sipv6\-multicast\-mld\-list\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string325 = /.{0,1000}\sipv6\-node\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string326 = /.{0,1000}\sipv6\-ra\-flood\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string327 = /.{0,1000}\sirc\-botnet\-channels\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string328 = /.{0,1000}\sirc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string329 = /.{0,1000}\sirc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string330 = /.{0,1000}\sirc\-sasl\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string331 = /.{0,1000}\sirc\-unrealircd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string332 = /.{0,1000}\siscsi\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string333 = /.{0,1000}\siscsi\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string334 = /.{0,1000}\sisns\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string335 = /.{0,1000}\sjdwp\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string336 = /.{0,1000}\sjdwp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string337 = /.{0,1000}\sjdwp\-inject\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string338 = /.{0,1000}\sjdwp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string339 = /.{0,1000}\sknx\-gateway\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string340 = /.{0,1000}\sknx\-gateway\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string341 = /.{0,1000}\skrb5\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string342 = /.{0,1000}\sldap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string343 = /.{0,1000}\sldap\-novell\-getpass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string344 = /.{0,1000}\sldap\-rootdse\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string345 = /.{0,1000}\sldap\-search\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string346 = /.{0,1000}\slexmark\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string347 = /.{0,1000}\sllmnr\-resolve\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string348 = /.{0,1000}\slltd\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string349 = /.{0,1000}\slu\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string350 = /.{0,1000}\smaxdb\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string351 = /.{0,1000}\smcafee\-epo\-agent\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string352 = /.{0,1000}\smembase\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string353 = /.{0,1000}\smembase\-http\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string354 = /.{0,1000}\smemcached\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string355 = /.{0,1000}\smetasploit\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string356 = /.{0,1000}\smetasploit\-msgrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string357 = /.{0,1000}\smetasploit\-xmlrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string358 = /.{0,1000}\smikrotik\-routeros\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string359 = /.{0,1000}\smmouse\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string360 = /.{0,1000}\smmouse\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string361 = /.{0,1000}\smodbus\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string362 = /.{0,1000}\smongodb\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string363 = /.{0,1000}\smongodb\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string364 = /.{0,1000}\smongodb\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string365 = /.{0,1000}\smqtt\-subscribe\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string366 = /.{0,1000}\smrinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string367 = /.{0,1000}\sMS15\-034\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string368 = /.{0,1000}\smsrpc\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string369 = /.{0,1000}\sms\-sql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string370 = /.{0,1000}\sms\-sql\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string371 = /.{0,1000}\sms\-sql\-dac\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string372 = /.{0,1000}\sms\-sql\-dump\-hashes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string373 = /.{0,1000}\sms\-sql\-empty\-password\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string374 = /.{0,1000}\sms\-sql\-hasdbaccess\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string375 = /.{0,1000}\sms\-sql\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string376 = /.{0,1000}\sms\-sql\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string377 = /.{0,1000}\sms\-sql\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string378 = /.{0,1000}\sms\-sql\-tables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string379 = /.{0,1000}\sms\-sql\-xp\-cmdshell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string380 = /.{0,1000}\smtrace\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string381 = /.{0,1000}\smurmur\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string382 = /.{0,1000}\smysql\-audit\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string383 = /.{0,1000}\smysql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string384 = /.{0,1000}\smysql\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string385 = /.{0,1000}\smysql\-dump\-hashes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string386 = /.{0,1000}\smysql\-empty\-password\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string387 = /.{0,1000}\smysql\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string388 = /.{0,1000}\smysql\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string389 = /.{0,1000}\smysql\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string390 = /.{0,1000}\smysql\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string391 = /.{0,1000}\smysql\-variables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string392 = /.{0,1000}\smysql\-vuln\-cve2012\-2122\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string393 = /.{0,1000}\snat\-pmp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string394 = /.{0,1000}\snat\-pmp\-mapport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string395 = /.{0,1000}\snbd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string396 = /.{0,1000}\snbns\-interfaces\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string397 = /.{0,1000}\snbstat\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string398 = /.{0,1000}\sncp\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string399 = /.{0,1000}\sncp\-serverinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string400 = /.{0,1000}\sndmp\-fs\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string401 = /.{0,1000}\sndmp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string402 = /.{0,1000}\snessus\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string403 = /.{0,1000}\snessus\-xmlrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string404 = /.{0,1000}\snetbus\-auth\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string405 = /.{0,1000}\snetbus\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string406 = /.{0,1000}\snetbus\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string407 = /.{0,1000}\snetbus\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string408 = /.{0,1000}\snexpose\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string409 = /.{0,1000}\snfs\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string410 = /.{0,1000}\snfs\-showmount\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string411 = /.{0,1000}\snfs\-statfs\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string412 = /.{0,1000}\snje\-node\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string413 = /.{0,1000}\snje\-pass\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string414 = /.{0,1000}\snntp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string415 = /.{0,1000}\snping\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string416 = /.{0,1000}\snrpe\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string417 = /.{0,1000}\sntp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string418 = /.{0,1000}\sntp\-monlist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string419 = /.{0,1000}\somp2\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string420 = /.{0,1000}\somp2\-enum\-targets\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string421 = /.{0,1000}\somron\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string422 = /.{0,1000}\sopenflow\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string423 = /.{0,1000}\sopenlookup\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string424 = /.{0,1000}\sopenvas\-otp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string425 = /.{0,1000}\sopenwebnet\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string426 = /.{0,1000}\soracle\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string427 = /.{0,1000}\soracle\-brute\-stealth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string428 = /.{0,1000}\soracle\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string429 = /.{0,1000}\soracle\-sid\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string430 = /.{0,1000}\soracle\-tns\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string431 = /.{0,1000}\sovs\-agent\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string432 = /.{0,1000}\sp2p\-conficker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string433 = /.{0,1000}\spath\-mtu\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string434 = /.{0,1000}\spcanywhere\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string435 = /.{0,1000}\spcworx\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string436 = /.{0,1000}\spgsql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string437 = /.{0,1000}\spjl\-info\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string438 = /.{0,1000}\spjl\-ready\-message\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string439 = /.{0,1000}\spop3\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string440 = /.{0,1000}\spop3\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string441 = /.{0,1000}\spop3\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string442 = /.{0,1000}\sport\-states\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string443 = /.{0,1000}\spptp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string444 = /.{0,1000}\spuppet\-naivesigning\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string445 = /.{0,1000}\sqconn\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string446 = /.{0,1000}\sqscan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string447 = /.{0,1000}\squake1\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string448 = /.{0,1000}\squake3\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string449 = /.{0,1000}\squake3\-master\-getservers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string450 = /.{0,1000}\srdp\-enum\-encryption\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string451 = /.{0,1000}\srdp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string452 = /.{0,1000}\srdp\-vuln\-ms12\-020\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string453 = /.{0,1000}\srealvnc\-auth\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string454 = /.{0,1000}\sredis\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string455 = /.{0,1000}\sredis\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string456 = /.{0,1000}\sresolveall\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string457 = /.{0,1000}\sreverse\-index\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string458 = /.{0,1000}\srexec\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string459 = /.{0,1000}\srfc868\-time\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string460 = /.{0,1000}\sriak\-http\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string461 = /.{0,1000}\srlogin\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string462 = /.{0,1000}\srmi\-dumpregistry\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string463 = /.{0,1000}\srmi\-vuln\-classloader\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string464 = /.{0,1000}\srpcap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string465 = /.{0,1000}\srpcap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string466 = /.{0,1000}\srpc\-grind\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string467 = /.{0,1000}\srpcinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string468 = /.{0,1000}\srsa\-vuln\-roca\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string469 = /.{0,1000}\srsync\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string470 = /.{0,1000}\srsync\-list\-modules\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string471 = /.{0,1000}\srtsp\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string472 = /.{0,1000}\srtsp\-url\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string473 = /.{0,1000}\srusers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string474 = /.{0,1000}\ss7\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string475 = /.{0,1000}\ssamba\-vuln\-cve\-2012\-1182\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string476 = /.{0,1000}\s\-\-script\ssmb\-vuln\-.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string477 = /.{0,1000}\sservicetags\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string478 = /.{0,1000}\sshodan\-api\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string479 = /.{0,1000}\ssip\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string480 = /.{0,1000}\ssip\-call\-spoof\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string481 = /.{0,1000}\ssip\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string482 = /.{0,1000}\ssip\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string483 = /.{0,1000}\ssip\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string484 = /.{0,1000}\sskypev2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string485 = /.{0,1000}\ssmb2\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string486 = /.{0,1000}\ssmb2\-security\-mode\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string487 = /.{0,1000}\ssmb2\-time\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string488 = /.{0,1000}\ssmb2\-vuln\-uptime\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string489 = /.{0,1000}\ssmb\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string490 = /.{0,1000}\ssmb\-double\-pulsar\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string491 = /.{0,1000}\ssmb\-enum\-domains\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string492 = /.{0,1000}\ssmb\-enum\-groups\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string493 = /.{0,1000}\ssmb\-enum\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string494 = /.{0,1000}\ssmb\-enum\-services\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string495 = /.{0,1000}\ssmb\-enum\-sessions\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string496 = /.{0,1000}\ssmb\-enum\-shares\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string497 = /.{0,1000}\ssmb\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string498 = /.{0,1000}\ssmb\-flood\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string499 = /.{0,1000}\ssmb\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string500 = /.{0,1000}\ssmb\-mbenum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string501 = /.{0,1000}\ssmb\-os\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string502 = /.{0,1000}\ssmb\-print\-text\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string503 = /.{0,1000}\ssmb\-protocols\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string504 = /.{0,1000}\ssmb\-psexec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string505 = /.{0,1000}\ssmb\-security\-mode\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string506 = /.{0,1000}\ssmb\-server\-stats\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string507 = /.{0,1000}\ssmb\-system\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string508 = /.{0,1000}\ssmb\-vuln\-conficker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string509 = /.{0,1000}\ssmb\-vuln\-cve2009\-3103\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string510 = /.{0,1000}\ssmb\-vuln\-cve\-2017\-7494\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string511 = /.{0,1000}\ssmb\-vuln\-ms06\-025\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string512 = /.{0,1000}\ssmb\-vuln\-ms07\-029\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string513 = /.{0,1000}\ssmb\-vuln\-ms08\-067\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string514 = /.{0,1000}\ssmb\-vuln\-ms10\-054\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string515 = /.{0,1000}\ssmb\-vuln\-ms10\-061\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string516 = /.{0,1000}\ssmb\-vuln\-ms17\-010\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string517 = /.{0,1000}\ssmb\-vuln\-regsvc\-dos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string518 = /.{0,1000}\ssmb\-vuln\-webexec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string519 = /.{0,1000}\ssmb\-webexec\-exploit\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string520 = /.{0,1000}\ssmtp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string521 = /.{0,1000}\ssmtp\-commands\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string522 = /.{0,1000}\ssmtp\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string523 = /.{0,1000}\ssmtp\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string524 = /.{0,1000}\ssmtp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string525 = /.{0,1000}\ssmtp\-open\-relay\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string526 = /.{0,1000}\ssmtp\-strangeport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string527 = /.{0,1000}\ssmtp\-vuln\-cve2010\-4344\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string528 = /.{0,1000}\ssmtp\-vuln\-cve2011\-1720\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string529 = /.{0,1000}\ssmtp\-vuln\-cve2011\-1764\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string530 = /.{0,1000}\ssmtp\-vuln\-cve2020\-28017\-through\-28026\-21nails\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string531 = /.{0,1000}\ssniffer\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string532 = /.{0,1000}\ssnmp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string533 = /.{0,1000}\ssnmp\-hh3c\-logins\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string534 = /.{0,1000}\ssnmp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string535 = /.{0,1000}\ssnmp\-interfaces\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string536 = /.{0,1000}\ssnmp\-ios\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string537 = /.{0,1000}\ssnmp\-netstat\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string538 = /.{0,1000}\ssnmp\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string539 = /.{0,1000}\ssnmp\-sysdescr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string540 = /.{0,1000}\ssnmp\-win32\-services\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string541 = /.{0,1000}\ssnmp\-win32\-shares\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string542 = /.{0,1000}\ssnmp\-win32\-software\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string543 = /.{0,1000}\ssnmp\-win32\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string544 = /.{0,1000}\ssocks\-auth\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string545 = /.{0,1000}\ssocks\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string546 = /.{0,1000}\ssocks\-open\-proxy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing (stealphy mode)
        // Reference: https://nmap.org/book/nse-usage.html
        $string547 = /.{0,1000}\s\-sS\s\-p\-\s\-\-min\-rate\=.{0,1000}\s\-Pn.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string548 = /.{0,1000}\sssh2\-enum\-algos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string549 = /.{0,1000}\sssh\-auth\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string550 = /.{0,1000}\sssh\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string551 = /.{0,1000}\sssh\-hostkey\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE scripts to check against log4shell or LogJam vulnerabilities (CVE-2021-44228). NSE scripts check most popular exposed services on the Internet. It is basic script where you can customize payload. Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/Diverto/nse-log4shell
        $string552 = /.{0,1000}\sssh\-log4shell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string553 = /.{0,1000}\sssh\-publickey\-acceptance\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string554 = /.{0,1000}\sssh\-run\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string555 = /.{0,1000}\ssshv1\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string556 = /.{0,1000}\sssl\-ccs\-injection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string557 = /.{0,1000}\sssl\-cert\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string558 = /.{0,1000}\sssl\-cert\-intaddr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string559 = /.{0,1000}\sssl\-date\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string560 = /.{0,1000}\sssl\-dh\-params\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string561 = /.{0,1000}\sssl\-enum\-ciphers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string562 = /.{0,1000}\sssl\-heartbleed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string563 = /.{0,1000}\sssl\-known\-key\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string564 = /.{0,1000}\sssl\-poodle\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string565 = /.{0,1000}\ssslv2\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string566 = /.{0,1000}\ssslv2\-drown\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string567 = /.{0,1000}\ssstp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string568 = /.{0,1000}\sstun\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string569 = /.{0,1000}\sstun\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string570 = /.{0,1000}\sstuxnet\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string571 = /.{0,1000}\ssupermicro\-ipmi\-conf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string572 = /.{0,1000}\s\-sV\s\-\-script\svulners\s.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string573 = /.{0,1000}\ssvn\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string574 = /.{0,1000}\stargets\-asn\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string575 = /.{0,1000}\stargets\-ipv6\-map4to6\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string576 = /.{0,1000}\stargets\-ipv6\-multicast\-echo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string577 = /.{0,1000}\stargets\-ipv6\-multicast\-invalid\-dst\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string578 = /.{0,1000}\stargets\-ipv6\-multicast\-mld\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string579 = /.{0,1000}\stargets\-ipv6\-multicast\-slaac\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string580 = /.{0,1000}\stargets\-ipv6\-wordlist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string581 = /.{0,1000}\stargets\-sniffer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string582 = /.{0,1000}\stargets\-traceroute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string583 = /.{0,1000}\stargets\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string584 = /.{0,1000}\steamspeak2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string585 = /.{0,1000}\stelnet\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string586 = /.{0,1000}\stelnet\-encryption\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string587 = /.{0,1000}\stelnet\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string588 = /.{0,1000}\stftp\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string589 = /.{0,1000}\stls\-alpn\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string590 = /.{0,1000}\stls\-nextprotoneg\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string591 = /.{0,1000}\stls\-ticketbleed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string592 = /.{0,1000}\stn3270\-screen\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string593 = /.{0,1000}\stor\-consensus\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string594 = /.{0,1000}\straceroute\-geolocation\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string595 = /.{0,1000}\stso\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string596 = /.{0,1000}\stso\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string597 = /.{0,1000}\subiquiti\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string598 = /.{0,1000}\sunittest\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string599 = /.{0,1000}\sunusual\-port\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string600 = /.{0,1000}\supnp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string601 = /.{0,1000}\suptime\-agent\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string602 = /.{0,1000}\surl\-snarf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string603 = /.{0,1000}\sventrilo\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string604 = /.{0,1000}\sversant\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string605 = /.{0,1000}\svmauthd\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string606 = /.{0,1000}\svmware\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string607 = /.{0,1000}\svnc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string608 = /.{0,1000}\svnc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string609 = /.{0,1000}\svnc\-title\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string610 = /.{0,1000}\svoldemort\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string611 = /.{0,1000}\svtam\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string612 = /.{0,1000}\svulners\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string613 = /.{0,1000}\svulscan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string614 = /.{0,1000}\svuze\-dht\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string615 = /.{0,1000}\swdb\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string616 = /.{0,1000}\sweblogic\-t3\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string617 = /.{0,1000}\swhois\-domain\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string618 = /.{0,1000}\swhois\-ip\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string619 = /.{0,1000}\swsdd\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string620 = /.{0,1000}\sx11\-access\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string621 = /.{0,1000}\sxdmcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string622 = /.{0,1000}\sxmlrpc\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string623 = /.{0,1000}\sxmpp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string624 = /.{0,1000}\sxmpp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string625 = /.{0,1000}\/acarsd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string626 = /.{0,1000}\/address\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string627 = /.{0,1000}\/afp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string628 = /.{0,1000}\/afp\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string629 = /.{0,1000}\/afp\-path\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string630 = /.{0,1000}\/afp\-serverinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string631 = /.{0,1000}\/afp\-showmount\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string632 = /.{0,1000}\/ajp\-auth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string633 = /.{0,1000}\/ajp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string634 = /.{0,1000}\/ajp\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string635 = /.{0,1000}\/ajp\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string636 = /.{0,1000}\/ajp\-request\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string637 = /.{0,1000}\/allseeingeye\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string638 = /.{0,1000}\/amqp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string639 = /.{0,1000}\/asn\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string640 = /.{0,1000}\/auth\-owners\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string641 = /.{0,1000}\/auth\-spoof\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string642 = /.{0,1000}\/backorifice\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string643 = /.{0,1000}\/backorifice\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string644 = /.{0,1000}\/bacnet\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string645 = /.{0,1000}\/banner\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string646 = /.{0,1000}\/bitcoin\-getaddr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string647 = /.{0,1000}\/bitcoin\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string648 = /.{0,1000}\/bitcoinrpc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string649 = /.{0,1000}\/bittorrent\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string650 = /.{0,1000}\/bjnp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string651 = /.{0,1000}\/broadcast\-ataoe\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string652 = /.{0,1000}\/broadcast\-avahi\-dos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string653 = /.{0,1000}\/broadcast\-bjnp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string654 = /.{0,1000}\/broadcast\-db2\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string655 = /.{0,1000}\/broadcast\-dhcp6\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string656 = /.{0,1000}\/broadcast\-dhcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string657 = /.{0,1000}\/broadcast\-dns\-service\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string658 = /.{0,1000}\/broadcast\-dropbox\-listener\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string659 = /.{0,1000}\/broadcast\-eigrp\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string660 = /.{0,1000}\/broadcast\-hid\-discoveryd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string661 = /.{0,1000}\/broadcast\-igmp\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string662 = /.{0,1000}\/broadcast\-jenkins\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string663 = /.{0,1000}\/broadcast\-listener\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string664 = /.{0,1000}\/broadcast\-ms\-sql\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string665 = /.{0,1000}\/broadcast\-netbios\-master\-browser\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string666 = /.{0,1000}\/broadcast\-networker\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string667 = /.{0,1000}\/broadcast\-novell\-locate\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string668 = /.{0,1000}\/broadcast\-ospf2\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string669 = /.{0,1000}\/broadcast\-pc\-anywhere\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string670 = /.{0,1000}\/broadcast\-pc\-duo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string671 = /.{0,1000}\/broadcast\-pim\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string672 = /.{0,1000}\/broadcast\-ping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string673 = /.{0,1000}\/broadcast\-pppoe\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string674 = /.{0,1000}\/broadcast\-rip\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string675 = /.{0,1000}\/broadcast\-ripng\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string676 = /.{0,1000}\/broadcast\-sonicwall\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string677 = /.{0,1000}\/broadcast\-sybase\-asa\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string678 = /.{0,1000}\/broadcast\-tellstick\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string679 = /.{0,1000}\/broadcast\-upnp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string680 = /.{0,1000}\/broadcast\-versant\-locate\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string681 = /.{0,1000}\/broadcast\-wake\-on\-lan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string682 = /.{0,1000}\/broadcast\-wpad\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string683 = /.{0,1000}\/broadcast\-wsdd\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string684 = /.{0,1000}\/broadcast\-xdmcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string685 = /.{0,1000}\/cassandra\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string686 = /.{0,1000}\/cassandra\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string687 = /.{0,1000}\/cccam\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string688 = /.{0,1000}\/cics\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string689 = /.{0,1000}\/cics\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string690 = /.{0,1000}\/cics\-user\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string691 = /.{0,1000}\/cics\-user\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string692 = /.{0,1000}\/citrix\-brute\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string693 = /.{0,1000}\/citrix\-enum\-apps\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string694 = /.{0,1000}\/citrix\-enum\-apps\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string695 = /.{0,1000}\/citrix\-enum\-servers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string696 = /.{0,1000}\/citrix\-enum\-servers\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string697 = /.{0,1000}\/clamav\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string698 = /.{0,1000}\/clock\-skew\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string699 = /.{0,1000}\/coap\-resources\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string700 = /.{0,1000}\/couchdb\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string701 = /.{0,1000}\/couchdb\-stats\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string702 = /.{0,1000}\/creds\-summary\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string703 = /.{0,1000}\/cups\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string704 = /.{0,1000}\/cups\-queue\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string705 = /.{0,1000}\/cvs\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string706 = /.{0,1000}\/cvs\-brute\-repository\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string707 = /.{0,1000}\/daap\-get\-library\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string708 = /.{0,1000}\/daytime\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string709 = /.{0,1000}\/db2\-das\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string710 = /.{0,1000}\/deluge\-rpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string711 = /.{0,1000}\/dhcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string712 = /.{0,1000}\/dicom\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string713 = /.{0,1000}\/dicom\-ping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string714 = /.{0,1000}\/dict\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string715 = /.{0,1000}\/distcc\-cve2004\-2687\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string716 = /.{0,1000}\/dns\-blacklist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string717 = /.{0,1000}\/dns\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string718 = /.{0,1000}\/dns\-cache\-snoop\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string719 = /.{0,1000}\/dns\-check\-zone\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string720 = /.{0,1000}\/dns\-client\-subnet\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string721 = /.{0,1000}\/dns\-fuzz\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string722 = /.{0,1000}\/dns\-ip6\-arpa\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string723 = /.{0,1000}\/dns\-nsec3\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string724 = /.{0,1000}\/dns\-nsec\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string725 = /.{0,1000}\/dns\-nsid\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string726 = /.{0,1000}\/dns\-random\-srcport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string727 = /.{0,1000}\/dns\-random\-txid\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string728 = /.{0,1000}\/dns\-recursion\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string729 = /.{0,1000}\/dns\-service\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string730 = /.{0,1000}\/dns\-srv\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string731 = /.{0,1000}\/dns\-update\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string732 = /.{0,1000}\/dns\-zeustracker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string733 = /.{0,1000}\/dns\-zone\-transfer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string734 = /.{0,1000}\/docker\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string735 = /.{0,1000}\/domcon\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string736 = /.{0,1000}\/domcon\-cmd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string737 = /.{0,1000}\/domino\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string738 = /.{0,1000}\/dpap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string739 = /.{0,1000}\/drda\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string740 = /.{0,1000}\/drda\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string741 = /.{0,1000}\/duplicates\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string742 = /.{0,1000}\/eap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string743 = /.{0,1000}\/enip\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string744 = /.{0,1000}\/epmd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string745 = /.{0,1000}\/eppc\-enum\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string746 = /.{0,1000}\/fcrdns\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string747 = /.{0,1000}\/finger\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string748 = /.{0,1000}\/fingerprint\-strings\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string749 = /.{0,1000}\/firewalk\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string750 = /.{0,1000}\/firewall\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string751 = /.{0,1000}\/flume\-master\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string752 = /.{0,1000}\/fox\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string753 = /.{0,1000}\/freelancer\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string754 = /.{0,1000}\/ftp\-anon\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string755 = /.{0,1000}\/ftp\-bounce\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string756 = /.{0,1000}\/ftp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string757 = /.{0,1000}\/ftp\-libopie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string758 = /.{0,1000}\/ftp\-proftpd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string759 = /.{0,1000}\/ftp\-syst\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string760 = /.{0,1000}\/ftp\-vsftpd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string761 = /.{0,1000}\/ftp\-vuln\-cve2010\-4221\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string762 = /.{0,1000}\/ganglia\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string763 = /.{0,1000}\/giop\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string764 = /.{0,1000}\/gkrellm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string765 = /.{0,1000}\/gopher\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string766 = /.{0,1000}\/gpsd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string767 = /.{0,1000}\/hadoop\-datanode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string768 = /.{0,1000}\/hadoop\-jobtracker\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string769 = /.{0,1000}\/hadoop\-namenode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string770 = /.{0,1000}\/hadoop\-secondary\-namenode\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string771 = /.{0,1000}\/hadoop\-tasktracker\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string772 = /.{0,1000}\/hbase\-master\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string773 = /.{0,1000}\/hbase\-region\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string774 = /.{0,1000}\/hddtemp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string775 = /.{0,1000}\/hnap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string776 = /.{0,1000}\/hostmap\-bfk\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string777 = /.{0,1000}\/hostmap\-crtsh\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string778 = /.{0,1000}\/hostmap\-robtex\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string779 = /.{0,1000}\/http\-adobe\-coldfusion\-apsa1301\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string780 = /.{0,1000}\/http\-affiliate\-id\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string781 = /.{0,1000}\/http\-apache\-negotiation\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string782 = /.{0,1000}\/http\-apache\-server\-status\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string783 = /.{0,1000}\/http\-aspnet\-debug\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string784 = /.{0,1000}\/http\-auth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string785 = /.{0,1000}\/http\-auth\-finder\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string786 = /.{0,1000}\/http\-avaya\-ipoffice\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string787 = /.{0,1000}\/http\-awstatstotals\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string788 = /.{0,1000}\/http\-axis2\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string789 = /.{0,1000}\/http\-backup\-finder\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string790 = /.{0,1000}\/http\-barracuda\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string791 = /.{0,1000}\/http\-bigip\-cookie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string792 = /.{0,1000}\/http\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string793 = /.{0,1000}\/http\-cakephp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string794 = /.{0,1000}\/http\-chrono\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string795 = /.{0,1000}\/http\-cisco\-anyconnect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string796 = /.{0,1000}\/http\-coldfusion\-subzero\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string797 = /.{0,1000}\/http\-comments\-displayer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string798 = /.{0,1000}\/http\-config\-backup\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string799 = /.{0,1000}\/http\-cookie\-flags\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string800 = /.{0,1000}\/http\-cors\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string801 = /.{0,1000}\/http\-cross\-domain\-policy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string802 = /.{0,1000}\/http\-csrf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string803 = /.{0,1000}\/http\-date\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string804 = /.{0,1000}\/http\-default\-accounts\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string805 = /.{0,1000}\/http\-devframework\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string806 = /.{0,1000}\/http\-dlink\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string807 = /.{0,1000}\/http\-dombased\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string808 = /.{0,1000}\/http\-domino\-enum\-passwords\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string809 = /.{0,1000}\/http\-drupal\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string810 = /.{0,1000}\/http\-drupal\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string811 = /.{0,1000}\/http\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string812 = /.{0,1000}\/http\-errors\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string813 = /.{0,1000}\/http\-exif\-spider\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string814 = /.{0,1000}\/http\-favicon\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string815 = /.{0,1000}\/http\-feed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string816 = /.{0,1000}\/http\-fetch\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string817 = /.{0,1000}\/http\-fileupload\-exploiter\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string818 = /.{0,1000}\/http\-form\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string819 = /.{0,1000}\/http\-form\-fuzzer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string820 = /.{0,1000}\/http\-frontpage\-login\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string821 = /.{0,1000}\/http\-generator\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string822 = /.{0,1000}\/http\-git\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string823 = /.{0,1000}\/http\-gitweb\-projects\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string824 = /.{0,1000}\/http\-google\-malware\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string825 = /.{0,1000}\/http\-grep\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string826 = /.{0,1000}\/http\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string827 = /.{0,1000}\/http\-hp\-ilo\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string828 = /.{0,1000}\/http\-huawei\-hg5xx\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string829 = /.{0,1000}\/http\-icloud\-findmyiphone\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string830 = /.{0,1000}\/http\-icloud\-sendmsg\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string831 = /.{0,1000}\/http\-iis\-short\-name\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string832 = /.{0,1000}\/http\-iis\-webdav\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string833 = /.{0,1000}\/http\-internal\-ip\-disclosure\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string834 = /.{0,1000}\/http\-joomla\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string835 = /.{0,1000}\/http\-jsonp\-detection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string836 = /.{0,1000}\/http\-lexmark\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string837 = /.{0,1000}\/http\-lfi\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string838 = /.{0,1000}\/http\-litespeed\-sourcecode\-download\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string839 = /.{0,1000}\/http\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string840 = /.{0,1000}\/http\-majordomo2\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string841 = /.{0,1000}\/http\-malware\-host\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string842 = /.{0,1000}\/http\-mcmp\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string843 = /.{0,1000}\/http\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string844 = /.{0,1000}\/http\-method\-tamper\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string845 = /.{0,1000}\/http\-mobileversion\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string846 = /.{0,1000}\/http\-nikto\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string847 = /.{0,1000}\/http\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string848 = /.{0,1000}\/http\-open\-proxy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string849 = /.{0,1000}\/http\-open\-redirect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string850 = /.{0,1000}\/http\-passwd\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string851 = /.{0,1000}\/http\-phpmyadmin\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string852 = /.{0,1000}\/http\-phpself\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string853 = /.{0,1000}\/http\-php\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string854 = /.{0,1000}\/http\-proxy\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string855 = /.{0,1000}\/http\-put\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string856 = /.{0,1000}\/http\-qnap\-nas\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string857 = /.{0,1000}\/http\-referer\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string858 = /.{0,1000}\/http\-rfi\-spider\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string859 = /.{0,1000}\/http\-robots\.txt\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string860 = /.{0,1000}\/http\-robtex\-reverse\-ip\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string861 = /.{0,1000}\/http\-robtex\-shared\-ns\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string862 = /.{0,1000}\/http\-sap\-netweaver\-leak\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string863 = /.{0,1000}\/http\-security\-headers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string864 = /.{0,1000}\/http\-server\-header\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string865 = /.{0,1000}\/http\-shellshock\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string866 = /.{0,1000}\/http\-sitemap\-generator\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string867 = /.{0,1000}\/http\-slowloris\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string868 = /.{0,1000}\/http\-slowloris\-check\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string869 = /.{0,1000}\/http\-sql\-injection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string870 = /.{0,1000}\/https\-redirect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string871 = /.{0,1000}\/http\-stored\-xss\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string872 = /.{0,1000}\/http\-svn\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string873 = /.{0,1000}\/http\-svn\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string874 = /.{0,1000}\/http\-tenda\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string875 = /.{0,1000}\/http\-title\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string876 = /.{0,1000}\/http\-tplink\-dir\-traversal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string877 = /.{0,1000}\/http\-trace\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string878 = /.{0,1000}\/http\-traceroute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string879 = /.{0,1000}\/http\-trane\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string880 = /.{0,1000}\/http\-unsafe\-output\-escaping\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string881 = /.{0,1000}\/http\-useragent\-tester\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string882 = /.{0,1000}\/http\-userdir\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string883 = /.{0,1000}\/http\-vhosts\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string884 = /.{0,1000}\/http\-virustotal\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string885 = /.{0,1000}\/http\-vlcstreamer\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string886 = /.{0,1000}\/http\-vmware\-path\-vuln\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string887 = /.{0,1000}\/http\-vuln\-cve2006\-3392\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string888 = /.{0,1000}\/http\-vuln\-cve2009\-3960\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string889 = /.{0,1000}\/http\-vuln\-cve2010\-0738\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string890 = /.{0,1000}\/http\-vuln\-cve2010\-2861\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string891 = /.{0,1000}\/http\-vuln\-cve2011\-3192\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string892 = /.{0,1000}\/http\-vuln\-cve2011\-3368\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string893 = /.{0,1000}\/http\-vuln\-cve2012\-1823\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string894 = /.{0,1000}\/http\-vuln\-cve2013\-0156\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string895 = /.{0,1000}\/http\-vuln\-cve2013\-6786\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string896 = /.{0,1000}\/http\-vuln\-cve2013\-7091\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string897 = /.{0,1000}\/http\-vuln\-cve2014\-2126\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string898 = /.{0,1000}\/http\-vuln\-cve2014\-2127\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string899 = /.{0,1000}\/http\-vuln\-cve2014\-2128\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string900 = /.{0,1000}\/http\-vuln\-cve2014\-2129\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string901 = /.{0,1000}\/http\-vuln\-cve2014\-3704\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string902 = /.{0,1000}\/http\-vuln\-cve2014\-8877\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string903 = /.{0,1000}\/http\-vuln\-cve2015\-1427\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string904 = /.{0,1000}\/http\-vuln\-cve2015\-1635\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string905 = /.{0,1000}\/http\-vuln\-cve2017\-1001000\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string906 = /.{0,1000}\/http\-vuln\-cve2017\-5638\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string907 = /.{0,1000}\/http\-vuln\-cve2017\-5689\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string908 = /.{0,1000}\/http\-vuln\-cve2017\-8917\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/vulnersCom/nmap-vulners
        $string909 = /.{0,1000}\/http\-vulners\-regex\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string910 = /.{0,1000}\/http\-vuln\-misfortune\-cookie\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string911 = /.{0,1000}\/http\-vuln\-wnr1000\-creds\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string912 = /.{0,1000}\/http\-waf\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string913 = /.{0,1000}\/http\-waf\-fingerprint\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string914 = /.{0,1000}\/http\-webdav\-scan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string915 = /.{0,1000}\/http\-wordpress\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string916 = /.{0,1000}\/http\-wordpress\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string917 = /.{0,1000}\/http\-wordpress\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string918 = /.{0,1000}\/http\-xssed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string919 = /.{0,1000}\/iax2\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string920 = /.{0,1000}\/iax2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string921 = /.{0,1000}\/icap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string922 = /.{0,1000}\/iec\-identify\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string923 = /.{0,1000}\/ike\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string924 = /.{0,1000}\/imap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string925 = /.{0,1000}\/imap\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string926 = /.{0,1000}\/imap\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string927 = /.{0,1000}\/impress\-remote\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string928 = /.{0,1000}\/informix\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string929 = /.{0,1000}\/informix\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string930 = /.{0,1000}\/informix\-tables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string931 = /.{0,1000}\/ip\-forwarding\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string932 = /.{0,1000}\/ip\-geolocation\-geoplugin\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string933 = /.{0,1000}\/ip\-geolocation\-ipinfodb\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string934 = /.{0,1000}\/ip\-geolocation\-map\-bing\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string935 = /.{0,1000}\/ip\-geolocation\-map\-google\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string936 = /.{0,1000}\/ip\-geolocation\-map\-kml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string937 = /.{0,1000}\/ip\-geolocation\-maxmind\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string938 = /.{0,1000}\/ip\-https\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string939 = /.{0,1000}\/ipidseq\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string940 = /.{0,1000}\/ipmi\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string941 = /.{0,1000}\/ipmi\-cipher\-zero\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string942 = /.{0,1000}\/ipmi\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string943 = /.{0,1000}\/ipv6\-multicast\-mld\-list\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string944 = /.{0,1000}\/ipv6\-node\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string945 = /.{0,1000}\/ipv6\-ra\-flood\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string946 = /.{0,1000}\/irc\-botnet\-channels\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string947 = /.{0,1000}\/irc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string948 = /.{0,1000}\/irc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string949 = /.{0,1000}\/irc\-sasl\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string950 = /.{0,1000}\/irc\-unrealircd\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string951 = /.{0,1000}\/iscsi\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string952 = /.{0,1000}\/iscsi\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string953 = /.{0,1000}\/isns\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string954 = /.{0,1000}\/jdwp\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string955 = /.{0,1000}\/jdwp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string956 = /.{0,1000}\/jdwp\-inject\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string957 = /.{0,1000}\/jdwp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string958 = /.{0,1000}\/knx\-gateway\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string959 = /.{0,1000}\/knx\-gateway\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string960 = /.{0,1000}\/krb5\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string961 = /.{0,1000}\/ldap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string962 = /.{0,1000}\/ldap\-novell\-getpass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string963 = /.{0,1000}\/ldap\-rootdse\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string964 = /.{0,1000}\/ldap\-search\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string965 = /.{0,1000}\/lexmark\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string966 = /.{0,1000}\/llmnr\-resolve\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string967 = /.{0,1000}\/lltd\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string968 = /.{0,1000}\/lu\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string969 = /.{0,1000}\/maxdb\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string970 = /.{0,1000}\/mcafee\-epo\-agent\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string971 = /.{0,1000}\/membase\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string972 = /.{0,1000}\/membase\-http\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string973 = /.{0,1000}\/memcached\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string974 = /.{0,1000}\/metasploit\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string975 = /.{0,1000}\/metasploit\-msgrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string976 = /.{0,1000}\/metasploit\-xmlrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string977 = /.{0,1000}\/mikrotik\-routeros\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string978 = /.{0,1000}\/mmouse\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string979 = /.{0,1000}\/mmouse\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string980 = /.{0,1000}\/modbus\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string981 = /.{0,1000}\/mongodb\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string982 = /.{0,1000}\/mongodb\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string983 = /.{0,1000}\/mongodb\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string984 = /.{0,1000}\/mqtt\-subscribe\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string985 = /.{0,1000}\/mrinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string986 = /.{0,1000}\/MS15\-034\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string987 = /.{0,1000}\/msrpc\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string988 = /.{0,1000}\/ms\-sql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string989 = /.{0,1000}\/ms\-sql\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string990 = /.{0,1000}\/ms\-sql\-dac\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string991 = /.{0,1000}\/ms\-sql\-dump\-hashes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string992 = /.{0,1000}\/ms\-sql\-empty\-password\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string993 = /.{0,1000}\/ms\-sql\-hasdbaccess\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string994 = /.{0,1000}\/ms\-sql\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string995 = /.{0,1000}\/ms\-sql\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string996 = /.{0,1000}\/ms\-sql\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string997 = /.{0,1000}\/ms\-sql\-tables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string998 = /.{0,1000}\/ms\-sql\-xp\-cmdshell\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string999 = /.{0,1000}\/mtrace\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1000 = /.{0,1000}\/murmur\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1001 = /.{0,1000}\/mysql\-audit\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1002 = /.{0,1000}\/mysql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1003 = /.{0,1000}\/mysql\-databases\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1004 = /.{0,1000}\/mysql\-dump\-hashes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1005 = /.{0,1000}\/mysql\-empty\-password\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1006 = /.{0,1000}\/mysql\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1007 = /.{0,1000}\/mysql\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1008 = /.{0,1000}\/mysql\-query\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1009 = /.{0,1000}\/mysql\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1010 = /.{0,1000}\/mysql\-variables\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1011 = /.{0,1000}\/mysql\-vuln\-cve2012\-2122\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1012 = /.{0,1000}\/nat\-pmp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1013 = /.{0,1000}\/nat\-pmp\-mapport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1014 = /.{0,1000}\/nbd\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1015 = /.{0,1000}\/nbns\-interfaces\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1016 = /.{0,1000}\/nbstat\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1017 = /.{0,1000}\/ncp\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1018 = /.{0,1000}\/ncp\-serverinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1019 = /.{0,1000}\/ndmp\-fs\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1020 = /.{0,1000}\/ndmp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1021 = /.{0,1000}\/nessus\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1022 = /.{0,1000}\/nessus\-xmlrpc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1023 = /.{0,1000}\/netbus\-auth\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1024 = /.{0,1000}\/netbus\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1025 = /.{0,1000}\/netbus\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1026 = /.{0,1000}\/netbus\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1027 = /.{0,1000}\/nexpose\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1028 = /.{0,1000}\/nfs\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1029 = /.{0,1000}\/nfs\-showmount\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1030 = /.{0,1000}\/nfs\-statfs\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1031 = /.{0,1000}\/nje\-node\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1032 = /.{0,1000}\/nje\-pass\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1033 = /.{0,1000}\/nntp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1034 = /.{0,1000}\/nping\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1035 = /.{0,1000}\/nrpe\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1036 = /.{0,1000}\/ntp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1037 = /.{0,1000}\/ntp\-monlist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1038 = /.{0,1000}\/omp2\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1039 = /.{0,1000}\/omp2\-enum\-targets\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1040 = /.{0,1000}\/omron\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1041 = /.{0,1000}\/openflow\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1042 = /.{0,1000}\/openlookup\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1043 = /.{0,1000}\/openvas\-otp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1044 = /.{0,1000}\/openwebnet\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1045 = /.{0,1000}\/oracle\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1046 = /.{0,1000}\/oracle\-brute\-stealth\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1047 = /.{0,1000}\/oracle\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1048 = /.{0,1000}\/oracle\-sid\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1049 = /.{0,1000}\/oracle\-tns\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1050 = /.{0,1000}\/ovs\-agent\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1051 = /.{0,1000}\/p2p\-conficker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1052 = /.{0,1000}\/path\-mtu\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1053 = /.{0,1000}\/pcanywhere\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1054 = /.{0,1000}\/pcworx\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1055 = /.{0,1000}\/pgsql\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string1056 = /.{0,1000}\/pjl\-info\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1057 = /.{0,1000}\/pjl\-ready\-message\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1058 = /.{0,1000}\/pop3\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1059 = /.{0,1000}\/pop3\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1060 = /.{0,1000}\/pop3\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1061 = /.{0,1000}\/port\-states\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1062 = /.{0,1000}\/pptp\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1063 = /.{0,1000}\/puppet\-naivesigning\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1064 = /.{0,1000}\/qconn\-exec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1065 = /.{0,1000}\/qscan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1066 = /.{0,1000}\/quake1\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1067 = /.{0,1000}\/quake3\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1068 = /.{0,1000}\/quake3\-master\-getservers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1069 = /.{0,1000}\/rdp\-enum\-encryption\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1070 = /.{0,1000}\/rdp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1071 = /.{0,1000}\/rdp\-vuln\-ms12\-020\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1072 = /.{0,1000}\/realvnc\-auth\-bypass\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1073 = /.{0,1000}\/redis\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1074 = /.{0,1000}\/redis\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1075 = /.{0,1000}\/resolveall\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1076 = /.{0,1000}\/reverse\-index\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1077 = /.{0,1000}\/rexec\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1078 = /.{0,1000}\/rfc868\-time\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1079 = /.{0,1000}\/riak\-http\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1080 = /.{0,1000}\/rlogin\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1081 = /.{0,1000}\/rmi\-dumpregistry\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1082 = /.{0,1000}\/rmi\-vuln\-classloader\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1083 = /.{0,1000}\/rpcap\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1084 = /.{0,1000}\/rpcap\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1085 = /.{0,1000}\/rpc\-grind\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1086 = /.{0,1000}\/rpcinfo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1087 = /.{0,1000}\/rsa\-vuln\-roca\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1088 = /.{0,1000}\/rsync\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1089 = /.{0,1000}\/rsync\-list\-modules\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1090 = /.{0,1000}\/rtsp\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1091 = /.{0,1000}\/rtsp\-url\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1092 = /.{0,1000}\/rusers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1093 = /.{0,1000}\/s7\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1094 = /.{0,1000}\/samba\-vuln\-cve\-2012\-1182\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1095 = /.{0,1000}\/servicetags\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1096 = /.{0,1000}\/shodan\-api\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1097 = /.{0,1000}\/sip\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1098 = /.{0,1000}\/sip\-call\-spoof\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1099 = /.{0,1000}\/sip\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1100 = /.{0,1000}\/sip\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1101 = /.{0,1000}\/skypev2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1102 = /.{0,1000}\/smb2\-capabilities\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1103 = /.{0,1000}\/smb2\-security\-mode\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1104 = /.{0,1000}\/smb2\-time\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1105 = /.{0,1000}\/smb2\-vuln\-uptime\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1106 = /.{0,1000}\/smb\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1107 = /.{0,1000}\/smb\-double\-pulsar\-backdoor\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1108 = /.{0,1000}\/smb\-enum\-domains\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1109 = /.{0,1000}\/smb\-enum\-groups\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1110 = /.{0,1000}\/smb\-enum\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1111 = /.{0,1000}\/smb\-enum\-services\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1112 = /.{0,1000}\/smb\-enum\-sessions\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1113 = /.{0,1000}\/smb\-enum\-shares\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1114 = /.{0,1000}\/smb\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1115 = /.{0,1000}\/smb\-flood\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1116 = /.{0,1000}\/smb\-ls\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1117 = /.{0,1000}\/smb\-mbenum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1118 = /.{0,1000}\/smb\-os\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1119 = /.{0,1000}\/smb\-print\-text\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1120 = /.{0,1000}\/smb\-protocols\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1121 = /.{0,1000}\/smb\-psexec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1122 = /.{0,1000}\/smb\-security\-mode\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1123 = /.{0,1000}\/smb\-server\-stats\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1124 = /.{0,1000}\/smb\-system\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1125 = /.{0,1000}\/smb\-vuln\-conficker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1126 = /.{0,1000}\/smb\-vuln\-cve2009\-3103\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1127 = /.{0,1000}\/smb\-vuln\-cve\-2017\-7494\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string1128 = /.{0,1000}\/smb\-vuln\-cve\-2020\-0796\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1129 = /.{0,1000}\/smb\-vuln\-ms06\-025\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1130 = /.{0,1000}\/smb\-vuln\-ms07\-029\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1131 = /.{0,1000}\/smb\-vuln\-ms08\-067\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1132 = /.{0,1000}\/smb\-vuln\-ms10\-054\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1133 = /.{0,1000}\/smb\-vuln\-ms10\-061\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1134 = /.{0,1000}\/smb\-vuln\-ms17\-010\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1135 = /.{0,1000}\/smb\-vuln\-regsvc\-dos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1136 = /.{0,1000}\/smb\-vuln\-webexec\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1137 = /.{0,1000}\/smb\-webexec\-exploit\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1138 = /.{0,1000}\/smtp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1139 = /.{0,1000}\/smtp\-commands\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1140 = /.{0,1000}\/smtp\-enum\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1141 = /.{0,1000}\/smtp\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1142 = /.{0,1000}\/smtp\-open\-relay\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1143 = /.{0,1000}\/smtp\-strangeport\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1144 = /.{0,1000}\/smtp\-vuln\-cve2010\-4344\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1145 = /.{0,1000}\/smtp\-vuln\-cve2011\-1720\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1146 = /.{0,1000}\/smtp\-vuln\-cve2011\-1764\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nccgroup/nmap-nse-vulnerability-scripts
        $string1147 = /.{0,1000}\/smtp\-vuln\-cve2020\-28017\-through\-28026\-21nails\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1148 = /.{0,1000}\/sniffer\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1149 = /.{0,1000}\/snmp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1150 = /.{0,1000}\/snmp\-hh3c\-logins\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1151 = /.{0,1000}\/snmp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1152 = /.{0,1000}\/snmp\-interfaces\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1153 = /.{0,1000}\/snmp\-ios\-config\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1154 = /.{0,1000}\/snmp\-netstat\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1155 = /.{0,1000}\/snmp\-processes\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1156 = /.{0,1000}\/snmp\-sysdescr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1157 = /.{0,1000}\/snmp\-win32\-services\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1158 = /.{0,1000}\/snmp\-win32\-shares\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1159 = /.{0,1000}\/snmp\-win32\-software\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1160 = /.{0,1000}\/snmp\-win32\-users\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1161 = /.{0,1000}\/socks\-auth\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1162 = /.{0,1000}\/socks\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1163 = /.{0,1000}\/socks\-open\-proxy\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1164 = /.{0,1000}\/ssh2\-enum\-algos\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1165 = /.{0,1000}\/ssh\-auth\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1166 = /.{0,1000}\/ssh\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1167 = /.{0,1000}\/ssh\-hostkey\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1168 = /.{0,1000}\/ssh\-publickey\-acceptance\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1169 = /.{0,1000}\/ssh\-run\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1170 = /.{0,1000}\/sshv1\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1171 = /.{0,1000}\/ssl\-ccs\-injection\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1172 = /.{0,1000}\/ssl\-cert\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1173 = /.{0,1000}\/ssl\-cert\-intaddr\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1174 = /.{0,1000}\/ssl\-date\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1175 = /.{0,1000}\/ssl\-dh\-params\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1176 = /.{0,1000}\/ssl\-enum\-ciphers\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1177 = /.{0,1000}\/ssl\-heartbleed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1178 = /.{0,1000}\/ssl\-known\-key\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1179 = /.{0,1000}\/ssl\-poodle\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1180 = /.{0,1000}\/sslv2\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1181 = /.{0,1000}\/sslv2\-drown\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1182 = /.{0,1000}\/sstp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1183 = /.{0,1000}\/stun\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1184 = /.{0,1000}\/stun\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1185 = /.{0,1000}\/stuxnet\-detect\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1186 = /.{0,1000}\/supermicro\-ipmi\-conf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1187 = /.{0,1000}\/svn\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1188 = /.{0,1000}\/targets\-asn\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1189 = /.{0,1000}\/targets\-ipv6\-map4to6\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1190 = /.{0,1000}\/targets\-ipv6\-multicast\-echo\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1191 = /.{0,1000}\/targets\-ipv6\-multicast\-invalid\-dst\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1192 = /.{0,1000}\/targets\-ipv6\-multicast\-mld\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1193 = /.{0,1000}\/targets\-ipv6\-multicast\-slaac\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1194 = /.{0,1000}\/targets\-ipv6\-wordlist\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1195 = /.{0,1000}\/targets\-sniffer\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1196 = /.{0,1000}\/targets\-traceroute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1197 = /.{0,1000}\/targets\-xml\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1198 = /.{0,1000}\/teamspeak2\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1199 = /.{0,1000}\/telnet\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1200 = /.{0,1000}\/telnet\-encryption\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1201 = /.{0,1000}\/telnet\-ntlm\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1202 = /.{0,1000}\/tftp\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1203 = /.{0,1000}\/tls\-alpn\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1204 = /.{0,1000}\/tls\-nextprotoneg\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1205 = /.{0,1000}\/tls\-ticketbleed\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1206 = /.{0,1000}\/tn3270\-screen\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1207 = /.{0,1000}\/tor\-consensus\-checker\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1208 = /.{0,1000}\/traceroute\-geolocation\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1209 = /.{0,1000}\/tso\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1210 = /.{0,1000}\/tso\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1211 = /.{0,1000}\/ubiquiti\-discovery\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1212 = /.{0,1000}\/unittest\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1213 = /.{0,1000}\/unusual\-port\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1214 = /.{0,1000}\/upnp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1215 = /.{0,1000}\/uptime\-agent\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1216 = /.{0,1000}\/url\-snarf\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1217 = /.{0,1000}\/ventrilo\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1218 = /.{0,1000}\/versant\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1219 = /.{0,1000}\/vmauthd\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1220 = /.{0,1000}\/vmware\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1221 = /.{0,1000}\/vnc\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1222 = /.{0,1000}\/vnc\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1223 = /.{0,1000}\/vnc\-title\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1224 = /.{0,1000}\/voldemort\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1225 = /.{0,1000}\/vtam\-enum\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1226 = /.{0,1000}\/vulners\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/cldrn/nmap-nse-scripts/tree/master/scripts
        $string1227 = /.{0,1000}\/vulscan\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1228 = /.{0,1000}\/vuze\-dht\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1229 = /.{0,1000}\/wdb\-version\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1230 = /.{0,1000}\/weblogic\-t3\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1231 = /.{0,1000}\/whois\-domain\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1232 = /.{0,1000}\/whois\-ip\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1233 = /.{0,1000}\/wsdd\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1234 = /.{0,1000}\/x11\-access\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1235 = /.{0,1000}\/xdmcp\-discover\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1236 = /.{0,1000}\/xmlrpc\-methods\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1237 = /.{0,1000}\/xmpp\-brute\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1238 = /.{0,1000}\/xmpp\-info\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1239 = /.{0,1000}krb5\-enum\-users\s.{0,1000}/ nocase ascii wide
        // Description: Nmap NSE Scripts. Nmap Network Mapper is a free and open source utility for network discovery and security auditing
        // Reference: https://svn.nmap.org/nmap/scripts/
        $string1240 = /.{0,1000}krb5\-enum\-users\..{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string1241 = /.{0,1000}nmap\s.{0,1000}\-\-script\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
