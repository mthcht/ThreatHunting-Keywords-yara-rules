rule Dendrobate
{
    meta:
        description = "Detection patterns for the tool 'Dendrobate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dendrobate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string1 = /.{0,1000}\sDendron\.exe.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string2 = /.{0,1000}\/Bates\.csproj.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string3 = /.{0,1000}\/Dendrobate\.git.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string4 = /.{0,1000}\/Dendron\.bin.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string5 = /.{0,1000}\/Dendron\.csproj.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string6 = /.{0,1000}\/Dendron\.exe.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string7 = /.{0,1000}\/Dendron\.sln.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string8 = /.{0,1000}\/hDendron\.cs.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string9 = /.{0,1000}\\Dendrobate\\.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string10 = /.{0,1000}\\Dendron\.bin.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string11 = /.{0,1000}\\Dendron\.exe.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string12 = /.{0,1000}\\Dendron\.sln.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string13 = /.{0,1000}Bates\.exe\s\-\-kill.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string14 = /.{0,1000}Bates\.exe\s\-\-listen.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string15 = /.{0,1000}Dendrobate\-master.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string16 = /.{0,1000}dendron.{0,1000}FileMonInject\.dll.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string17 = /.{0,1000}EasyHook\-Managed.{0,1000}InjectionLoader\.cs.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string18 = /.{0,1000}EasyHook\-Managed.{0,1000}WOW64Bypass\..{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string19 = /.{0,1000}EasyHook\-Managed\/LocalHook\.cs.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string20 = /.{0,1000}FuzzySecurity\/Dendrobate.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string21 = /.{0,1000}ManagedEasyHook\.dll.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string22 = /.{0,1000}NativeEasyHook32\.dll.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string23 = /.{0,1000}NativeEasyHook64\.dll.{0,1000}/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string24 = /.{0,1000}P8CuaPrgwBjunvZxJcgq.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
