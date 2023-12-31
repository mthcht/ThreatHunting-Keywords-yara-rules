rule Coercer
{
    meta:
        description = "Detection patterns for the tool 'Coercer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Coercer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string1 = /\scoerce\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-listener\-ip/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string2 = /\sCoercer\.py/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string3 = /\sfuzz\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-target/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string4 = /\s\-\-only\-known\-exploit\-paths/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string5 = /\/coercer\.egg\-info/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string6 = /\/Coercer\.git/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string7 = /\/Coercer\.py/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string8 = /\/Coercer\/.{0,1000}\.py/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string9 = /\\Coercer\.py/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string10 = /Coercer\scoerce/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string11 = /Coercer\sfuzz/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string12 = /Coercer\sscan/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string13 = /coercer\.core/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string14 = /coercer\.methods/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string15 = /coercer\.models/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string16 = /coercer\.network/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string17 = /Coercer\.py\s/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string18 = /coercer\.structures/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string19 = /coercer\/core\/loader/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string20 = /find_and_load_coerce_methods/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string21 = /generate_exploit_path_from_template/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string22 = /install\scoercer/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string23 = /p0dalirius\/Coercer/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string24 = /podalirius\@protonmail\.com/ nocase ascii wide

    condition:
        any of them
}
