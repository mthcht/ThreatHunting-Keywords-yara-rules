rule SimpleHelp
{
    meta:
        description = "Detection patterns for the tool 'SimpleHelp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleHelp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string1 = /\"SimpleHelp\sRemote\sPrinter\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string2 = /\/simplehelper64\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string3 = /\\JWrapper\-SimpleHelp\sRemote\sWork/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string4 = /\\JWrapper\-SimpleHelp\sTechnician/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string5 = /\\JWrapper\-SimpleHelp\sTechnician\\/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string6 = /\\Programs\\SimpleHelp\sRemote\sWork\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string7 = /\\Programs\\SimpleHelp\sTechnician/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string8 = /\\remote\saccess\ssession\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string9 = /\\remote\saccess\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string10 = /\\Remote\sAccessEmbedExample\.html/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string11 = /\\Remote\sAccess\-java\-online\.jar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string12 = /\\remote\ssupport\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string13 = /\\Remote\sSupportEmbedExample\.html/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string14 = /\\remoteaccess\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string15 = /\\SafeBoot\\Network\\ShTemporaryService/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string16 = /\\SafeBoot\\Network\\SimpleHelp\sServer/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string17 = /\\Services\\SimpleHelp\sServer/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string18 = /\\simplegateway\.service\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string19 = /\\SimpleHelp\sTechnicianEmbedExample\.html/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string20 = /\\SimpleHelp\.RemoteWork\.127_0_0_1/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string21 = /\\SimpleHelp\.Technician\.127_0_0_1/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string22 = /\\simplehelper64\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string23 = /\\simplehelp\-rw\\shell/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string24 = /\\simplehelpuninstall\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string25 = /\\SimpleService\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string26 = /\\StopSimpleGatewayService\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string27 = /\\winpty\-agent64\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string28 = /\>SimpleHelp\sLtd\</ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string29 = /bin\\Remote\sAccessLauncher\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string30 = /Elevate.{0,1000}\\elev_win\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string31 = /firewall\sadd\srule\s\"name\=SH\sRemote\sAccess\sService\sLauncher\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string32 = /firewall\sadd\srule\s\"name\=SH\sRemote\sAccess\sService\sUpdater\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string33 = /firewall\sadd\srule\s\"name\=SH\sRemote\sAccess\sService\"/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string34 = /Manage\sRemote\sAccess\sService\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string35 = /Program\sFiles\\SimpleHelp/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string36 = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,1000}\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string37 = /Remote\sAccessECompatibility\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string38 = /Remote\sAccess\-linux32arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string39 = /Remote\sAccess\-linux32arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string40 = /Remote\sAccess\-linux32\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string41 = /Remote\sAccess\-linux32\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string42 = /Remote\sAccess\-linux64arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string43 = /Remote\sAccess\-linux64arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string44 = /Remote\sAccess\-linux64\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string45 = /Remote\sAccess\-linux64\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string46 = /Remote\sAccess\-macos\-intel\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string47 = /Remote\sAccess\-macos\-intel\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string48 = /Remote\sAccess\-macos\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string49 = /Remote\sAccess\-macos\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string50 = /Remote\sAccess\-windows32\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string51 = /Remote\sAccess\-windows32\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string52 = /Remote\sAccess\-windows64\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string53 = /remote\saccess\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string54 = /Remote\sAccess\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string55 = /Remote\sSupport\-java\-online\.jar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string56 = /Remote\sSupport\-linux32arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string57 = /Remote\sSupport\-linux32arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string58 = /Remote\sSupport\-linux32\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string59 = /Remote\sSupport\-linux32\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string60 = /Remote\sSupport\-linux64arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string61 = /Remote\sSupport\-linux64arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string62 = /Remote\sSupport\-linux64\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string63 = /Remote\sSupport\-linux64\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string64 = /Remote\sSupport\-macos\-intel\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string65 = /Remote\sSupport\-macos\-intel\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string66 = /Remote\sSupport\-macos\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string67 = /Remote\sSupport\-macos\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string68 = /Remote\sSupport\-windows32\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string69 = /Remote\sSupport\-windows32\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string70 = /Remote\sSupport\-windows64\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string71 = /remote\ssupport\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string72 = /Remote\sSupport\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string73 = /remote\swork\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string74 = /Remote\sWork\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string75 = /SimpleHelp\s\-\ssimple\-help\.com/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string76 = /simplehelp\sremote\swork\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string77 = /simplehelp\sremote\sworkwinlauncher\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string78 = /SimpleHelp\sRemote\sWorkWinLauncher\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string79 = /SimpleHelp\sTechnician\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string80 = /simplehelp\stechnician\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string81 = /SimpleHelp\sTechnician\-java\-online\.jar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string82 = /SimpleHelp\sTechnician\-linux32arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string83 = /SimpleHelp\sTechnician\-linux32arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string84 = /SimpleHelp\sTechnician\-linux32\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string85 = /SimpleHelp\sTechnician\-linux32\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string86 = /SimpleHelp\sTechnician\-linux64arm\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string87 = /SimpleHelp\sTechnician\-linux64arm\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string88 = /SimpleHelp\sTechnician\-linux64\-offline\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string89 = /SimpleHelp\sTechnician\-linux64\-online\.tar/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string90 = /SimpleHelp\sTechnician\-macos\-intel\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string91 = /SimpleHelp\sTechnician\-macos\-intel\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string92 = /SimpleHelp\sTechnician\-macos\-offline\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string93 = /SimpleHelp\sTechnician\-macos\-online\.dmg/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string94 = /SimpleHelp\sTechnician\-windows32\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string95 = /SimpleHelp\sTechnician\-windows32\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string96 = /SimpleHelp\sTechnician\-windows64\-offline\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string97 = /simplehelp\stechnician\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string98 = /SimpleHelp\sTechnician\-windows64\-online\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string99 = /simplehelp\stechnicianwinlauncher\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string100 = /SimpleHelp\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string101 = /simplehelp\.technician\.127_0_0_1/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string102 = /SimpleHelp\-allplatforms\.zip/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string103 = /simplehelpcustomer\.exe/ nocase ascii wide
        // Description: SimpleHelp is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string104 = /SimpleHelp\-install\-64\.exe/ nocase ascii wide

    condition:
        any of them
}
