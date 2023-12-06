rule InjectProc
{
    meta:
        description = "Detection patterns for the tool 'InjectProc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InjectProc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Process injection is a very popular method to hide malicious behavior of code and are heavily used by malware authors.There are several techniques. which are commonly used: DLL injection. process replacement (a.k.a process hollowing). hook injection and APC injection.
        // Reference: https://github.com/secrary/InjectProc
        $string1 = /InjectProc/ nocase ascii wide

    condition:
        any of them
}
