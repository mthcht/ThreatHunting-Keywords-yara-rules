rule NoFilter
{
    meta:
        description = "Detection patterns for the tool 'NoFilter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoFilter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string1 = /.{0,1000}\/NoFilter\.cpp.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string2 = /.{0,1000}\/NoFilter\.exe.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string3 = /.{0,1000}\/NoFilter\.git.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string4 = /.{0,1000}\/NoFilter\.sln.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string5 = /.{0,1000}\/NoFilter\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string6 = /.{0,1000}\\NoFilter\.cpp.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string7 = /.{0,1000}\\NoFilter\.exe.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string8 = /.{0,1000}\\NoFilter\.sln.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string9 = /.{0,1000}\\NoFilter\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string10 = /.{0,1000}2CFB9E9E\-479D\-4E23\-9A8E\-18C92E06B731.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string11 = /.{0,1000}deepinstinct\/NoFilter.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string12 = /.{0,1000}NoFilter\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string13 = /.{0,1000}NoFilter\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string14 = /.{0,1000}WfpEscalation\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
