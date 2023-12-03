rule BloodHound
{
    meta:
        description = "Detection patterns for the tool 'BloodHound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BloodHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string1 = /.{0,1000}\\BloodHound\.exe.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string2 = /.{0,1000}\\BloodHoundGui\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string3 = /.{0,1000}\\BloodHound\-win32\-X64.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string4 = /.{0,1000}_BloodHound\.zip.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string5 = /.{0,1000}AzureHound\.ps1.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string6 = /.{0,1000}azurehound\/v2.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string7 = /.{0,1000}BloodHound\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string8 = /.{0,1000}bloodhound\.bin.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string9 = /.{0,1000}BloodHoundAD.{0,1000}/ nocase ascii wide
        // Description: an adversary with local admin access to an AD-joined computer can dump the cleartext password from LSA secrets of any sMSAs installed on this computer
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string10 = /.{0,1000}DumpSMSAPassword.{0,1000}/ nocase ascii wide
        // Description: Kerberoasting With PowerView
        // Reference: https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
        $string11 = /.{0,1000}Get\-DomainSPNTicket.{0,1000}/ nocase ascii wide
        // Description: BloodHound is a single page Javascript web application. built on top of Linkurious. compiled with Electron. with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment
        // Reference: https://github.com/BloodHoundAD/BloodHound
        $string12 = /.{0,1000}SharpHound\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
