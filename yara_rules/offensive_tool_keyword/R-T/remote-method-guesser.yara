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
        $string1 = /.{0,1000}\senum\s127\.0\.0\.1\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string2 = /.{0,1000}\/remote\-method\-guesser\.git.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string3 = /.{0,1000}\/tmp\/wordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string4 = /.{0,1000}0\.0\.0\.0:4444.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string5 = /.{0,1000}0\.0\.0\.0:4445.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string6 = /.{0,1000}docker\sbuild\s\-t\srmg\s\..{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string7 = /.{0,1000}jdk.{0,1000}\-activator\-rce\-test\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string8 = /.{0,1000}jdk.{0,1000}\-call\-rce\-test\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string9 = /.{0,1000}jdk.{0,1000}\-dgc\-rce\-test\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string10 = /.{0,1000}jdk.{0,1000}\-method\-rce\-test\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string11 = /.{0,1000}jdk.{0,1000}\-reg\-bypass\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string12 = /.{0,1000}nc\s\-vlp\s4444.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string13 = /.{0,1000}nc\s\-vlp\s4445.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string14 = /.{0,1000}qtc\-de\/remote\-method\-guesser.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string15 = /.{0,1000}remote\-method\-guesser\/rmg.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string16 = /.{0,1000}remote\-method\-guesser\-master.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string17 = /.{0,1000}rmg\sbind\s.{0,1000}\sjmxrmi\s\-\-bind\-objid\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string18 = /.{0,1000}rmg\sbind\s.{0,1000}127\.0\.0\.1:.{0,1000}\-\-localhost\-bypass.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string19 = /.{0,1000}rmg\scall\s.{0,1000}\s\-\-plugin\sGenericPrint\.jar.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string20 = /.{0,1000}rmg\scall\s.{0,1000}\s\-\-signature\s.{0,1000}\s\-\-bound\-name\splain\-server.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string21 = /.{0,1000}rmg\scodebase\s.{0,1000}http.{0,1000}\s\-\-component\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string22 = /.{0,1000}rmg\scodebase\s.{0,1000}java\.util\.HashMap\s.{0,1000}\-\-bound\-name\slegacy\-service.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string23 = /.{0,1000}rmg\senum\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string24 = /.{0,1000}rmg\sguess\s.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string25 = /.{0,1000}rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string26 = /.{0,1000}rmg\slisten\s.{0,1000}\sCommonsCollections.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string27 = /.{0,1000}rmg\slisten\s0\.0\.0\.0\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string28 = /.{0,1000}rmg\sobjid\s.{0,1000}\[.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string29 = /.{0,1000}rmg\sroguejmx\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string30 = /.{0,1000}rmg\sscan\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string31 = /.{0,1000}rmg\sscan\s.{0,1000}\s\-\-ports\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string32 = /.{0,1000}rmg\sserial\s.{0,1000}\sAnTrinh\s.{0,1000}\s\-\-component\s.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string33 = /.{0,1000}rmg\sserial\s.{0,1000}CommonsCollections.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string34 = /.{0,1000}rmg\-.{0,1000}\-jar\-with\-dependencies\.jar.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string35 = /.{0,1000}rmg.{0,1000}\-\-yso.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string36 = /.{0,1000}\-\-ssrf\s\-\-gopher\s\-\-encode\s\-\-scan\-action\sfilter\-bypass.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string37 = /.{0,1000}wordlists.{0,1000}rmg\.txt.{0,1000}/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string38 = /.{0,1000}wordlists.{0,1000}rmiscout\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
