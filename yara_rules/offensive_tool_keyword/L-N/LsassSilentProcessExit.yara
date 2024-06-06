rule LsassSilentProcessExit
{
    meta:
        description = "Detection patterns for the tool 'LsassSilentProcessExit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LsassSilentProcessExit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string1 = /\/LsassSilentProcessExit\.git/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string2 = /\\LsassSilentProcessExit/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string3 = /\\SilentProcessExit\.sln/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string4 = /887e0ff0707e46e7f309f6e12eaddd4161b6b3aa88a705857ac55590cdc4c64a/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string5 = /daf3ed8ab5cb22d59e4b1de343f15e343c7e2383547f38f550b1e18a3cf8d11d/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string6 = /deepinstinct\/LsassSilentProcessExit/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string7 = /E82BCAD1\-0D2B\-4E95\-B382\-933CF78A8128/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string8 = /LsassSilentProcessExit\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string9 = /LsassSilentProcessExit\.exe/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string10 = /LsassSilentProcessExit\.vcxproj/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string11 = /LsassSilentProcessExit\-master/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string12 = /Setting\sup\sGFlags\s\&\sSilentProcessExit\ssettings\sin\sregistry\?/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string13 = /SilentProcessExitRegistrySetter\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string14 = /SilentProcessExitRegistrySetter\.exe/ nocase ascii wide

    condition:
        any of them
}
