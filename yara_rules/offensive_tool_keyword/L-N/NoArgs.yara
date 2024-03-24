rule NoArgs
{
    meta:
        description = "Detection patterns for the tool 'NoArgs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoArgs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string1 = /\/NoArgs\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string2 = /\/NoArgs\.git/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string3 = /\[i\]\sArgument\sSpoofed\./ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string4 = /\\NoArgs\.cpp/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string5 = /\\NoArgs\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string6 = /\\NoArgs\.exe\.config/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string7 = /\\NoArgs\.exe\.log/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string8 = /\\NoArgs_Encrypted\.exe/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string9 = /6a14782fd71e08ded40b8652783cb49695b09e4abbaaf8c22cc22d582032191f/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string10 = /8c7d64cec00aafa23884f1bb28337ef6ce49f2f90605800217f635526e38541d/ nocase ascii wide
        // Description: NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.
        // Reference: https://github.com/oh-az/NoArgs
        $string11 = /oh\-az\/NoArgs/ nocase ascii wide

    condition:
        any of them
}
