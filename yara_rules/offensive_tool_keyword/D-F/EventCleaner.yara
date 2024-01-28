rule EventCleaner
{
    meta:
        description = "Detection patterns for the tool 'EventCleaner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventCleaner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string1 = /\/EventCleaner\.cpp/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string2 = /\/EventCleaner\.exe/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string3 = /\/EventCleaner\.git/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string4 = /\[\!\]\sinject\sdll\sinto\slog\sprocess\sfailure\s/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string5 = /\[\+\]\sdelete\ssingle\sevent\slog\ssucc/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string6 = /\[\+\]\ssecurity\sevtx\sfile\shandle\sunlock\ssucc/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string7 = /\\\\\.\\\\pipe\\\\kangaroo/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string8 = /\\EventCleaner\.cpp/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string9 = /\\EventCleaner\.exe/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string10 = /\\EventCleaner\.log/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string11 = /\\EventCleaner\.pdb/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string12 = /\\EventCleaner\.sln/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string13 = /\\EventCleaner\-master/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string14 = /0A2B3F8A\-EDC2\-48B5\-A5FC\-DE2AC57C8990/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string15 = /D8A76296\-A666\-46C7\-9CA0\-254BA97E3B7C/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string16 = /eventcleaner\sclosehandle/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string17 = /eventcleaner\ssuspend/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string18 = /EventCleaner\.exe\s/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string19 = /EventCleaner\.iobj/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string20 = /EventCleaner\\Debug\\/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string21 = /net\sstop\s\\\"windows\sevent\slog\\\"/ nocase ascii wide
        // Description: erase specified records from Windows event logs
        // Reference: https://github.com/QAX-A-Team/EventCleaner
        $string22 = /QAX\-A\-Team\/EventCleaner/ nocase ascii wide

    condition:
        any of them
}
