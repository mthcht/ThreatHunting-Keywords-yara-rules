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
        $string1 = /.{0,1000}\saction\=BackdoorLNK\s.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string2 = /.{0,1000}\saction\=CreateService\sservicename\=.{0,1000}\scommand\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string3 = /.{0,1000}\saction\=ElevatedRegistryKey\skeyname\=Debug\skeypath.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string4 = /.{0,1000}\saction\=ElevatedUserInitKey\scommand\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string5 = /.{0,1000}\saction\=JunctionFolder\sdllpath\=.{0,1000}\.dll\sguid\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string6 = /.{0,1000}\saction\=NewLNK\sfilepath\=.{0,1000}\"\slnkname\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string7 = /.{0,1000}\saction\=ScheduledTask\staskname\=.{0,1000}\scommand\=.{0,1000}runasuser.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string8 = /.{0,1000}\saction\=ScheduledTaskAction\staskname\=.{0,1000}\scommand\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string9 = /.{0,1000}\saction\=SchTaskCOMHijack\sclsid\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string10 = /.{0,1000}\saction\=UserRegistryKey\skeyname\=Debug\skeypath\=HKCU:.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string11 = /.{0,1000}\saction\=WMIEventSub\scommand\=.{0,1000}\seventname\=.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string12 = /.{0,1000}\.exe\saction\=GetScheduledTaskCOMHandler.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string13 = /.{0,1000}\.exe\saction\=ListRunningServices.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string14 = /.{0,1000}\.exe\saction\=ListScheduledTasks.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string15 = /.{0,1000}\.exe\saction\=ListTaskNames.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string16 = /.{0,1000}\/0xthirteen\/.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string17 = /.{0,1000}\/SharpStay\.git.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string18 = /.{0,1000}\/SharpStay\/.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string19 = /.{0,1000}2963C954\-7B1E\-47F5\-B4FA\-2FC1F0D56AEA.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string20 = /.{0,1000}action\=SchTaskCOMHijack\s.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string21 = /.{0,1000}SharpStay\.csproj.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string22 = /.{0,1000}Sharpstay\.exe\s.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string23 = /.{0,1000}SharpStay\.sln.{0,1000}/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string24 = /.{0,1000}SharpStay\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
