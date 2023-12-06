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
        $string1 = /\sExrop\(.{0,1000}\/bin\// nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string2 = /\simport\sExrop/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string3 = /\/avoid_badchars\.py/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string4 = /\/ChainBuilder\.py/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string5 = /\/d4em0n\/exrop/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string6 = /\/exploit_orw\.py/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string7 = /\/rop_emporium/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string8 = /from\sExrop\simport\s/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string9 = /from\spwn\simport\s/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string10 = /rop\.find_gadgets/ nocase ascii wide
        // Description: Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints
        // Reference: https://github.com/d4em0n/exrop
        $string11 = /RopChain\.py/ nocase ascii wide

    condition:
        any of them
}
