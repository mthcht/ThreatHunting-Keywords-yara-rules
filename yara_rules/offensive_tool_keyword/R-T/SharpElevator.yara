rule SharpElevator
{
    meta:
        description = "Detection patterns for the tool 'SharpElevator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpElevator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string1 = /\sSharpElevator\.exe/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string2 = /\/SharpElevator\.exe/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string3 = /\/SharpElevator\.git/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string4 = /\[\+\]\sWOOT\!\sCreated\selevated\sprocess\s/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string5 = /\\SharpElevator\.cs/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string6 = /\\SharpElevator\.exe/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string7 = /\\SharpElevator\.sln/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string8 = /378f6e87219651f96e607e40c229e5f17df4ad71836409881fe3cc77c6780ac7/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string9 = /42BDEFC0\-0BAE\-43DF\-97BB\-C805ABFBD078/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string10 = /6a31601415f4b02531aa031b1f246cec9f652f62927bc9b3c4443aac9c2ff625/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string11 = /a36ffb4f22598b5e983ef16251df49deb94ad0c41a8a1768503efe4d7e16ea40/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string12 = /a67edb34ce2c10bb5c170445344da4ad809932ff8e82e2b6c45a260d5a47a859/ nocase ascii wide
        // Description: SharpElevator is a C# implementation of Elevator for UAC bypass
        // Reference: https://github.com/eladshamir/SharpElevator
        $string13 = /eladshamir\/SharpElevator/ nocase ascii wide

    condition:
        any of them
}
