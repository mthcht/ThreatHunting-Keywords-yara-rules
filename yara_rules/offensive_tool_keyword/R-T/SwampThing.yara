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
        $string1 = /.{0,1000}\s\-FakeCmdLine\s.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string2 = /.{0,1000}\s\-RealCmdLine\s.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string3 = /.{0,1000}\\SpoofCmdLine\\TheThing.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string4 = /.{0,1000}\\TheThing\.exe.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string5 = /.{0,1000}master\/SwampThing.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string6 = /.{0,1000}SwampThing\.exe.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string7 = /.{0,1000}SwampThing\.pdb.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string8 = /.{0,1000}SwampThing\.sln.{0,1000}/ nocase ascii wide
        // Description: SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state - rewrite the PEB - resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing
        $string9 = /SwampThing\.csproj/ nocase ascii wide

    condition:
        any of them
}
