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
        $string1 = /.{0,1000}\spy2exe.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string2 = /.{0,1000}\/py2exe\/.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string3 = /.{0,1000}\\py2exe.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string4 = /.{0,1000}py2exe\s.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string5 = /.{0,1000}py2exe.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string6 = /.{0,1000}py2exe.{0,1000}\.msi\s.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string7 = /.{0,1000}py2exe.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string8 = /.{0,1000}py2exe\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string9 = /.{0,1000}py2exe\-.{0,1000}\.whl.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string10 = /.{0,1000}py2exe\.build_exe.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string11 = /.{0,1000}py2exe\.freeze.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string12 = /.{0,1000}py2exe\.git.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string13 = /.{0,1000}py2exe_setuptools\.py.{0,1000}/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string14 = /.{0,1000}py2exe\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
