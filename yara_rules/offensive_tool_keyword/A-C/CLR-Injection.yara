rule CLR_Injection
{
    meta:
        description = "Detection patterns for the tool 'CLR-Injection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CLR-Injection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string1 = /\sCLR\-Injection_x64\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string2 = /\sCLR\-Injection_x86\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string3 = /\/CLR\-Injection\.git/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string4 = /\/CLR\-Injection_x64\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string5 = /\/CLR\-Injection_x86\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string6 = /\\CLR\-Injection_x64\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string7 = /\\CLR\-Injection_x86\.bat/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string8 = /\\CLR\-Injection\-main/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string9 = /3gstudent\/CLR\-Injection/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string10 = /695d04c8162644e98cb0e68926b1cc9f47398e0ddd86255453c26b7619c88f10/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string11 = /6cbd17824d093c835adebf81d9d2e3c1fd56db6dcec461c1cf72f0e3b5ba52f5/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string12 = /https\:\/\/raw\.githubusercontent\.com\/.{0,1000}\/msg_x64\.dll/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string13 = /https\:\/\/raw\.githubusercontent\.com\/.{0,1000}\/test\/master\/msg\.dll/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string14 = /REG\.EXE\sADD\s.{0,1000}\s\/V\sThreadingModel\s\/T\sREG_SZ\s\/D\sApartment\s\/F/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string15 = /REG\.EXE\sADD\s.{0,1000}\s\/VE\s\/T\sREG_SZ\s\/D\s.{0,1000}\\msg\.dll/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string16 = /REG\.EXE\sADD\s.{0,1000}\s\/VE\s\/T\sREG_SZ\s\/D\s.{0,1000}\\msg_x64\.dll/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string17 = /wmic\sENVIRONMENT\screate\sname\=\"COR_ENABLE_PROFILING\"\,username\=\"\%username\%\"\,VariableValue\=\"1\"/ nocase ascii wide
        // Description: Use CLR to inject all the .NET apps
        // Reference: https://github.com/3gstudent/CLR-Injection
        $string18 = /wmic\sENVIRONMENT\screate\sname\=\"COR_PROFILER\"\,username\=\"\%username\%\"\,VariableValue\=\"\{11111111\-1111\-1111\-1111\-111111111111\}\"/ nocase ascii wide

    condition:
        any of them
}
