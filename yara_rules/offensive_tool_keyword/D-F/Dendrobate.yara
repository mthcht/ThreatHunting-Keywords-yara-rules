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
        $string1 = /\sDendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string2 = /\/Bates\.csproj/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string3 = /\/Dendrobate\.git/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string4 = /\/Dendron\.bin/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string5 = /\/Dendron\.csproj/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string6 = /\/Dendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string7 = /\/Dendron\.sln/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string8 = /\/hDendron\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string9 = /\\Dendrobate\\/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string10 = /\\Dendron\.bin/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string11 = /\\Dendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string12 = /\\Dendron\.sln/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string13 = /Bates\.exe\s\-\-kill/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string14 = /Bates\.exe\s\-\-listen/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string15 = /Dendrobate\-master/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string16 = /dendron.{0,1000}FileMonInject\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string17 = /EasyHook\-Managed.{0,1000}InjectionLoader\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string18 = /EasyHook\-Managed.{0,1000}WOW64Bypass\./ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string19 = /EasyHook\-Managed\/LocalHook\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string20 = /FuzzySecurity\/Dendrobate/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string21 = /ManagedEasyHook\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string22 = /NativeEasyHook32\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string23 = /NativeEasyHook64\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string24 = /P8CuaPrgwBjunvZxJcgq/ nocase ascii wide

    condition:
        any of them
}
