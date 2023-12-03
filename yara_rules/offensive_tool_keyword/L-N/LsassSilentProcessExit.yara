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
        $string1 = /.{0,1000}\/LsassSilentProcessExit\.git.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string2 = /.{0,1000}\\LsassSilentProcessExit.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string3 = /.{0,1000}\\SilentProcessExit\.sln.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string4 = /.{0,1000}deepinstinct\/LsassSilentProcessExit.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string5 = /.{0,1000}E82BCAD1\-0D2B\-4E95\-B382\-933CF78A8128.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string6 = /.{0,1000}LsassSilentProcessExit\.cpp.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string7 = /.{0,1000}LsassSilentProcessExit\.exe.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string8 = /.{0,1000}LsassSilentProcessExit\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string9 = /.{0,1000}LsassSilentProcessExit\-master.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string10 = /.{0,1000}Setting\sup\sGFlags\s\&\sSilentProcessExit\ssettings\sin\sregistry\?.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string11 = /.{0,1000}SilentProcessExitRegistrySetter\.cpp.{0,1000}/ nocase ascii wide
        // Description: Command line interface to dump LSASS memory to disk via SilentProcessExit
        // Reference: https://github.com/deepinstinct/LsassSilentProcessExit
        $string12 = /.{0,1000}SilentProcessExitRegistrySetter\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
