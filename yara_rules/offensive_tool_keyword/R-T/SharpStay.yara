rule SharpStay
{
    meta:
        description = "Detection patterns for the tool 'SharpStay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpStay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string1 = /\saction\=BackdoorLNK\s/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string2 = /\saction\=CreateService\sservicename\=.{0,1000}\scommand\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string3 = /\saction\=ElevatedRegistryKey\skeyname\=Debug\skeypath/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string4 = /\saction\=ElevatedUserInitKey\scommand\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string5 = /\saction\=JunctionFolder\sdllpath\=.{0,1000}\.dll\sguid\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string6 = /\saction\=NewLNK\sfilepath\=.{0,1000}\"\slnkname\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string7 = /\saction\=ScheduledTask\staskname\=.{0,1000}\scommand\=.{0,1000}runasuser/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string8 = /\saction\=ScheduledTaskAction\staskname\=.{0,1000}\scommand\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string9 = /\saction\=SchTaskCOMHijack\sclsid\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string10 = /\saction\=UserRegistryKey\skeyname\=Debug\skeypath\=HKCU\:/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string11 = /\saction\=WMIEventSub\scommand\=.{0,1000}\seventname\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string12 = /\.exe\saction\=GetScheduledTaskCOMHandler/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string13 = /\.exe\saction\=ListRunningServices/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string14 = /\.exe\saction\=ListScheduledTasks/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string15 = /\.exe\saction\=ListTaskNames/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string16 = /\/0xthirteen\// nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string17 = /\/SharpStay\.git/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string18 = /\/SharpStay\// nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string19 = /\[\+\]\sCreated\sElevated\sHKLM\:/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string20 = /\[\+\]\sUpdated\sElevated\sHKLM\:Software\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Winlogon\skey\sUserInit/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string21 = /0xthirteen\/SharpStay/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string22 = /2963C954\-7B1E\-47F5\-B4FA\-2FC1F0D56AEA/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string23 = /2963C954\-7B1E\-47F5\-B4FA\-2FC1F0D56AEA/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string24 = /action\=SchTaskCOMHijack\s/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string25 = /SharpStay\.csproj/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string26 = /Sharpstay\.exe/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string27 = /SharpStay\.sln/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string28 = /SharpStay\-master/ nocase ascii wide

    condition:
        any of them
}
