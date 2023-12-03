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
        $string1 = /.{0,1000}\scoerce\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-listener\-ip.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string2 = /.{0,1000}\sCoercer\.py.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string3 = /.{0,1000}\sfuzz\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-target.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string4 = /.{0,1000}\s\-\-only\-known\-exploit\-paths.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string5 = /.{0,1000}\/coercer\.egg\-info.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string6 = /.{0,1000}\/Coercer\.git.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string7 = /.{0,1000}\/Coercer\.py.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string8 = /.{0,1000}\/Coercer\/.{0,1000}\.py/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string9 = /.{0,1000}\\Coercer\.py.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string10 = /.{0,1000}Coercer\scoerce.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string11 = /.{0,1000}Coercer\sfuzz.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string12 = /.{0,1000}Coercer\sscan.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string13 = /.{0,1000}coercer\.core.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string14 = /.{0,1000}coercer\.methods.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string15 = /.{0,1000}coercer\.models.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string16 = /.{0,1000}coercer\.network.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string17 = /.{0,1000}Coercer\.py\s.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string18 = /.{0,1000}coercer\.structures.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string19 = /.{0,1000}coercer\/core\/loader.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string20 = /.{0,1000}find_and_load_coerce_methods.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string21 = /.{0,1000}generate_exploit_path_from_template.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string22 = /.{0,1000}install\scoercer.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string23 = /.{0,1000}p0dalirius\/Coercer.{0,1000}/ nocase ascii wide
        // Description: A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods.
        // Reference: https://github.com/p0dalirius/Coercer
        $string24 = /.{0,1000}podalirius\@protonmail\.com.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
