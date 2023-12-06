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
        $string1 = /\/DllNotificationInjection\.git/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string2 = /0A1C2C46\-33F7\-4D4C\-B8C6\-1FC9B116A6DF/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string3 = /DllNotificationInjection\.cpp/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string4 = /DllNotificationInjection\.exe/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string5 = /DllNotificationInjection\.sln/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string6 = /DllNotificationInjection\.vcxproj/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string7 = /DllNotificationInjection\-master/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string8 = /ShellcodeTemplate\.x64\.bin/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string9 = /ShorSec\/DllNotificationInjection/ nocase ascii wide

    condition:
        any of them
}
