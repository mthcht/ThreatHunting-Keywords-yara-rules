rule Exrop
{
    meta:
        description = "Detection patterns for the tool 'Exrop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Exrop"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string1 = /.{0,1000}\sExrop\(.{0,1000}\/bin\/.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string2 = /.{0,1000}\simport\sExrop.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string3 = /.{0,1000}\/avoid_badchars\.py.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string4 = /.{0,1000}\/ChainBuilder\.py.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string5 = /.{0,1000}\/d4em0n\/exrop.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string6 = /.{0,1000}\/exploit_orw\.py.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string7 = /.{0,1000}\/rop_emporium.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string8 = /.{0,1000}from\sExrop\simport\s.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string9 = /.{0,1000}from\spwn\simport\s.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string10 = /.{0,1000}rop\.find_gadgets.{0,1000}/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string11 = /.{0,1000}RopChain\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
