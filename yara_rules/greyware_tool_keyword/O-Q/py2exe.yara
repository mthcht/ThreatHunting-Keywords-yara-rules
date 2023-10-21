rule py2exe
{
    meta:
        description = "Detection patterns for the tool 'py2exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "py2exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string1 = /\spy2exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string2 = /\/py2exe\// nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string3 = /\\py2exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string4 = /py2exe\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string5 = /py2exe.*\.exe\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string6 = /py2exe.*\.msi\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string7 = /py2exe.*\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string8 = /py2exe\-.*\.tar\.gz/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string9 = /py2exe\-.*\.whl/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string10 = /py2exe\.build_exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string11 = /py2exe\.freeze/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string12 = /py2exe\.git/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string13 = /py2exe_setuptools\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string14 = /py2exe\-master\.zip/ nocase ascii wide

    condition:
        any of them
}