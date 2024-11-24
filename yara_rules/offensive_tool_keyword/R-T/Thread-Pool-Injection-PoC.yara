rule Thread_Pool_Injection_PoC
{
    meta:
        description = "Detection patterns for the tool 'Thread-Pool-Injection-PoC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Thread-Pool-Injection-PoC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string1 = /\/Thread\-Pool\-Injection\-PoC\.git/ nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string2 = "1AFD1BA3-028A-4E0F-82A8-095F38694ECF" nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string3 = "Modify the TP_POOL linked list Flinks and Blinks to point to the malicious task" nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string4 = /MY_MESSAGE\s\\"I\sdid\sit\sfor\sthe\svine\.\\"/ nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string5 = /ThreadPoolInjection\.lastbuildstate/ nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string6 = "Thread-Pool-Injection-PoC-main" nocase ascii wide
        // Description: Proof of concept code for thread pool based process injection in Windows.
        // Reference: https://github.com/Uri3n/Thread-Pool-Injection-PoC
        $string7 = "Uri3n/Thread-Pool-Injection-PoC" nocase ascii wide

    condition:
        any of them
}
