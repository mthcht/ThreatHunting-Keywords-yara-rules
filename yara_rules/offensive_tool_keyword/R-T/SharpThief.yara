rule SharpThief
{
    meta:
        description = "Detection patterns for the tool 'SharpThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string1 = /\/SharpThief\.git/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string2 = /\/SharpThief\/tarball/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string3 = /\/SharpThief\/zipball/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string4 = /\\SharpThief\\/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string5 = /\\SharpThief\-main/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string6 = /\>SharpThief\</ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string7 = /025280A3\-24F7\-4C55\-9B5E\-D08124A52546/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string8 = /2759a95c63a2af0eed9d3202d961ddb72d4da05ea44653d400f9003e0a492064/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string9 = /2990d1f4243fdfc99c3da1be020ee516ef530be55e2769d2526e4672e32b40f5/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string10 = /5374b615af370b5b03281366c6561f4ebb4f0f2716e8005f07cc4572d865b80a/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string11 = /84074bcee24f8ee02ce2011e88471d900bc85cace4967b1273c634a7dba5496b/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string12 = /aa659878813ee6b5ecb42d5d069fc48255b10337a357eb70fb5c002996c77239/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string13 = /d06d9e05ba5582691f8d5939cbbc37e171260c088a60770e2d45c27c9f1ac2ed/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string14 = /e7c9a0a34bad12057b3c39fb42106b7e095d8b64e9b68010ca8cf516a908c262/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string15 = /fa1b7e541e359317e69e48d0f089cfe83a6c8acf04d4c0ed44d76b38cc97e40f/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string16 = /INotGreen\/SharpThief/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string17 = /SharpThief\.csproj/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string18 = /SharpThief\.exe/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string19 = /SharpThief\.pdb/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string20 = /SharpThief\.Properties/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string21 = /SharpThief\.resources\.dll/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string22 = /SharpThief\.resources\.exe/ nocase ascii wide
        // Description: A one-click program to steal the icon, resource information, version information, modification time, and digital signature (invalid) to make the program appear legitimate
        // Reference: https://github.com/INotGreen/SharpThief
        $string23 = /SharpThief\.sln/ nocase ascii wide

    condition:
        any of them
}
