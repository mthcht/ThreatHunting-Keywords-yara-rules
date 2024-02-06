rule remote_method_guesser
{
    meta:
        description = "Detection patterns for the tool 'remote-method-guesser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remote-method-guesser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string1 = /\senum\s127\.0\.0\.1\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string2 = /\/remote\-method\-guesser\.git/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string3 = /\/tmp\/wordlist\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string4 = /0\.0\.0\.0\:4444/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string5 = /0\.0\.0\.0\:4445/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string6 = /docker\sbuild\s\-t\srmg\s\./ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string7 = /jdk.{0,1000}\-activator\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string8 = /jdk.{0,1000}\-call\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string9 = /jdk.{0,1000}\-dgc\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string10 = /jdk.{0,1000}\-method\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string11 = /jdk.{0,1000}\-reg\-bypass\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string12 = /nc\s\-vlp\s4444/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string13 = /nc\s\-vlp\s4445/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string14 = /qtc\-de\/remote\-method\-guesser/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string15 = /remote\-method\-guesser\/rmg/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string16 = /remote\-method\-guesser\-master/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string17 = /rmg\sbind\s.{0,1000}\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string18 = /rmg\sbind\s.{0,1000}127\.0\.0\.1\:.{0,1000}\-\-localhost\-bypass/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string19 = /rmg\scall\s.{0,1000}\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string20 = /rmg\scall\s.{0,1000}\s\-\-signature\s.{0,1000}\s\-\-bound\-name\splain\-server/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string21 = /rmg\scodebase\s.{0,1000}http.{0,1000}\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string22 = /rmg\scodebase\s.{0,1000}java\.util\.HashMap\s.{0,1000}\-\-bound\-name\slegacy\-service/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string23 = /rmg\senum\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string24 = /rmg\sguess\s.{0,1000}\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string25 = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string26 = /rmg\slisten\s.{0,1000}\sCommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string27 = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string28 = /rmg\sobjid\s.{0,1000}\[/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string29 = /rmg\sroguejmx\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string30 = /rmg\sscan\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string31 = /rmg\sscan\s.{0,1000}\s\-\-ports\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string32 = /rmg\sserial\s.{0,1000}\sAnTrinh\s.{0,1000}\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string33 = /rmg\sserial\s.{0,1000}CommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string34 = /rmg\-.{0,1000}\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string35 = /rmg.{0,1000}\-\-yso/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string36 = /\-\-ssrf\s\-\-gopher\s\-\-encode\s\-\-scan\-action\sfilter\-bypass/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string37 = /wordlists.{0,1000}rmg\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string38 = /wordlists.{0,1000}rmiscout\.txt/ nocase ascii wide

    condition:
        any of them
}
