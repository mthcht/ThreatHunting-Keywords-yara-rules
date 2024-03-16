rule winsos_poc
{
    meta:
        description = "Detection patterns for the tool 'winsos-poc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winsos-poc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string1 = /\/src\/winsos\.cpp/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string2 = /\/winsos\.exe/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string3 = /\/winsos\-poc\.git/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string4 = /\[\+\]\sThe\sDLL\shas\sbeen\sinjected\sinto\sngentask\.exe\svia\sDLL\sSide\-Loading/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string5 = /\[x\]\sFailed\sto\slocate\sthe\sngentask\.exe\sbinary\sin\sthe\sWinSxS\sdirectory/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string6 = /\\winsos\.cpp/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string7 = /\\winsos\.exe/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string8 = /http\:\/\/127\.0\.0\.1\:8080\/target\.dll/ nocase ascii wide
        // Description: A PoC demonstrating code execution via DLL Side-Loading in WinSxS binaries.
        // Reference: https://github.com/thiagopeixoto/winsos-poc
        $string9 = /thiagopeixoto\/winsos\-poc/ nocase ascii wide

    condition:
        any of them
}
