rule spring_core_rce
{
    meta:
        description = "Detection patterns for the tool 'spring-core-rce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spring-core-rce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CVE-2022-22965 : about spring core rce
        // Reference: https://github.com/Mr-xn/spring-core-rce
        $string1 = /.{0,1000}\/spring\-core\-rce.{0,1000}/ nocase ascii wide
        // Description: CVE-2022-22965 : about spring core rce
        // Reference: https://github.com/Mr-xn/spring-core-rce
        $string2 = /.{0,1000}cat\s\.\/apache\-tomcat\-8\.5\.77\/webapps\/ROOT\/tomcatwar\.jsp/ nocase ascii wide
        // Description: github user infosec hosting exploitation tools
        // Reference: https://github.com/Mr-xn/spring-core-rce
        $string3 = /.{0,1000}github.{0,1000}\/Mr\-xn\/.{0,1000}/ nocase ascii wide
        // Description: CVE-2022-22965 : about spring core rce
        // Reference: https://github.com/Mr-xn/spring-core-rce
        $string4 = /.{0,1000}spring\-core\-rce.{0,1000}ROOT\.war.{0,1000}/ nocase ascii wide
        // Description: CVE-2022-22965 : about spring core rce
        // Reference: https://github.com/Mr-xn/spring-core-rce
        $string5 = /.{0,1000}target\/tomcatwar\.jsp\?pwd\=j\&cmd\=.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
