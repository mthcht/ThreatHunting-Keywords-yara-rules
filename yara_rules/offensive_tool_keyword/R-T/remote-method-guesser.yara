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
        $string4 = /0\.0\.0\.0:4444/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string5 = /0\.0\.0\.0:4445/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string6 = /docker\sbuild\s\-t\srmg\s\./ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string7 = /jdk.*\-activator\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string8 = /jdk.*\-call\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string9 = /jdk.*\-dgc\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string10 = /jdk.*\-method\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string11 = /jdk.*\-reg\-bypass\.txt/ nocase ascii wide
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
        $string17 = /rmg\sbind\s.*\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string18 = /rmg\sbind\s.*127\.0\.0\.1:.*\-\-localhost\-bypass/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string19 = /rmg\scall\s.*\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string20 = /rmg\scall\s.*\s\-\-signature\s.*\s\-\-bound\-name\splain\-server/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string21 = /rmg\scodebase\s.*http.*\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string22 = /rmg\scodebase\s.*java\.util\.HashMap\s.*\-\-bound\-name\slegacy\-service/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string23 = /rmg\senum\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string24 = /rmg\sguess\s.*\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string25 = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string26 = /rmg\slisten\s.*\sCommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string27 = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string28 = /rmg\sobjid\s.*\[/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string29 = /rmg\sroguejmx\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string30 = /rmg\sscan\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string31 = /rmg\sscan\s.*\s\-\-ports\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string32 = /rmg\sserial\s.*\sAnTrinh\s.*\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string33 = /rmg\sserial\s.*CommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string34 = /rmg\-.*\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string35 = /rmg.*\-\-yso/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string36 = /\-\-ssrf\s\-\-gopher\s\-\-encode\s\-\-scan\-action\sfilter\-bypass/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string37 = /wordlists.*rmg\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string38 = /wordlists.*rmiscout\.txt/ nocase ascii wide

    condition:
        any of them
}