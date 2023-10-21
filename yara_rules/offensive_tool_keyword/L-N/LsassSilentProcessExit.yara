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
        $string4 = /deepinstinct\/LsassSilentProcessExit/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string5 = /E82BCAD1\-0D2B\-4E95\-B382\-933CF78A8128/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string6 = /LsassSilentProcessExit\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string7 = /LsassSilentProcessExit\.exe/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string8 = /LsassSilentProcessExit\.vcxproj/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string9 = /LsassSilentProcessExit\-master/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string10 = /Setting\sup\sGFlags\s\&\sSilentProcessExit\ssettings\sin\sregistry\?/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string11 = /SilentProcessExitRegistrySetter\.cpp/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string12 = /SilentProcessExitRegistrySetter\.exe/ nocase ascii wide

    condition:
        any of them
}