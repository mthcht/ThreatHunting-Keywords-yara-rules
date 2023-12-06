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
        $string1 = /\/NoFilter\.cpp/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string2 = /\/NoFilter\.exe/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string3 = /\/NoFilter\.git/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string4 = /\/NoFilter\.sln/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string5 = /\/NoFilter\.vcxproj/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string6 = /\\NoFilter\.cpp/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string7 = /\\NoFilter\.exe/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string8 = /\\NoFilter\.sln/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string9 = /\\NoFilter\.vcxproj/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string10 = /2CFB9E9E\-479D\-4E23\-9A8E\-18C92E06B731/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string11 = /deepinstinct\/NoFilter/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string12 = /NoFilter\.exe\s/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string13 = /NoFilter\-main\.zip/ nocase ascii wide
        // Description: Tool for abusing the Windows Filtering Platform for privilege escalation. It can launch a new console as NT AUTHORITY\SYSTEM or as another user that is logged on to the machine.
        // Reference: https://github.com/deepinstinct/NoFilter
        $string14 = /WfpEscalation\.exe/ nocase ascii wide

    condition:
        any of them
}
