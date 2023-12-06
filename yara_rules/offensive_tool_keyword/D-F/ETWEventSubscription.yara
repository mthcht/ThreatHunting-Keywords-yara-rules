rule ETWEventSubscription
{
    meta:
        description = "Detection patterns for the tool 'ETWEventSubscription' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETWEventSubscription"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs currently either when any user logs in or a specified process is started - the DoEvil() method is executed.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ETWEventSubscription
        $string1 = /DoEvil\(\)/ nocase ascii wide
        // Description: Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs currently either when any user logs in or a specified process is started - the DoEvil() method is executed.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ETWEventSubscription
        $string2 = /ETWEventSubscription.{0,1000}Program\.cs/ nocase ascii wide
        // Description: Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs currently either when any user logs in or a specified process is started - the DoEvil() method is executed.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ETWEventSubscription
        $string3 = /ETWEventSubscription\.exe.{0,1000}\s\-ProcStart\s/ nocase ascii wide
        // Description: Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs currently either when any user logs in or a specified process is started - the DoEvil() method is executed.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ETWEventSubscription
        $string4 = /ETWEventSubscription\.exe.{0,1000}\s\-UserLogon/ nocase ascii wide
        // Description: Similar to WMI event subscriptions but leverages Event Tracing for Windows. When the event on the system occurs currently either when any user logs in or a specified process is started - the DoEvil() method is executed.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ETWEventSubscription
        $string5 = /OffensiveCSharp.{0,1000}ETWEventSubscription/ nocase ascii wide

    condition:
        any of them
}
