rule SharpExfil
{
    meta:
        description = "Detection patterns for the tool 'SharpExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string1 = /\/SharpExfil\.git/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string2 = /\/Upload\-OneDrive\.exe/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string3 = /\\Upload\-OneDrive\.csproj/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string4 = /\\Upload\-OneDrive\.exe/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string5 = /\\Upload\-OneDrive\.sln/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string6 = ">Upload-OneDrive<" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string7 = "1723ab71aa08741de80ab99fa08291b4066e632466c47ade2884b3739bf244b0" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string8 = "5de78ea9-73a8-4c53-9d5e-3a893e439a3a" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string9 = "adm1nPanda/SharpExfil" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string10 = "f7ff8ee96535ad845f70c8a978366b33d7934132dda00de017fa5b09fd11a55a" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string11 = /https\:\/\/graph\.microsoft\.com\/v1\.0\/drive\/root\:\/testfoldera\/\{file_name\}\:\/createUploadSession/ nocase ascii wide

    condition:
        any of them
}
