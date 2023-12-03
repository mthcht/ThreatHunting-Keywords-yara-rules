rule DllNotificationInjection
{
    meta:
        description = "Detection patterns for the tool 'DllNotificationInjection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllNotificationInjection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string1 = /.{0,1000}\/DllNotificationInjection\.git.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string2 = /.{0,1000}0A1C2C46\-33F7\-4D4C\-B8C6\-1FC9B116A6DF.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string3 = /.{0,1000}DllNotificationInjection\.cpp.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string4 = /.{0,1000}DllNotificationInjection\.exe.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string5 = /.{0,1000}DllNotificationInjection\.sln.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string6 = /.{0,1000}DllNotificationInjection\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string7 = /.{0,1000}DllNotificationInjection\-master.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string8 = /.{0,1000}ShellcodeTemplate\.x64\.bin.{0,1000}/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string9 = /.{0,1000}ShorSec\/DllNotificationInjection.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
