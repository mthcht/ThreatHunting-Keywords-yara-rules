rule SwampThing
{
    meta:
        description = "Detection patterns for the tool 'SwampThing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SwampThing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string1 = /\s\-FakeCmdLine\s/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string2 = /\s\-RealCmdLine\s/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string3 = /\\SpoofCmdLine\\TheThing/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string4 = /\\TheThing\.exe/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string5 = /master\/SwampThing/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string6 = /SwampThing\.exe/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string7 = /SwampThing\.pdb/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string8 = /SwampThing\.sln/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string9 = /SwampThing\.csproj/ nocase ascii wide

    condition:
        any of them
}
