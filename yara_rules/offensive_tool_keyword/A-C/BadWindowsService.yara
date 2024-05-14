rule BadWindowsService
{
    meta:
        description = "Detection patterns for the tool 'BadWindowsService' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadWindowsService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string1 = /\sBadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string2 = /\/BadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string3 = /\/BadWindowsService\.git/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string4 = /\\BadWindowsService\.cs/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string5 = /\\BadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string6 = /\\BadWindowsService\.sln/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string7 = /\\CurrentControlSet\\Services\\BadWindowsService/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string8 = /1a88b6412bb1e6349948bc6abdc0eebb5df61cc8c0a7ec9709310a77dbc7bccb/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string9 = /320ed251abc046f440dc0e76d00864d6cf5f65dee61988898d86c18e5513a8c9/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string10 = /347e20ccd42d4346d9a1cb3255d77b493d3b1b52be12f72ccaa9085d6b5dd30f/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string11 = /43A031B0\-E040\-4D5E\-B477\-02651F5E3D62/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string12 = /6d820b495719031338017f6138fae3546f549e9e816274554f6c21a77149b778/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string13 = /9a717740140d1848e3b2641af0a517cea689409951cb1262737b06ec398180e3/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string14 = /acd65a0c933308d9a867fb3701e39787a386708fbaabd907d41b3decdb481ca2/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string15 = /B474B962\-A46B\-4D35\-86F3\-E8BA120C88C0/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string16 = /BadWindowsService_v1\.0\.7z/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string17 = /BadWindowsService_v1\.0\.zip/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string18 = /cc8bb64ef855405aeb66e480e8e7a2a65f61d495718fed2825083916cedd5e4c/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string19 = /eladshamir\/BadWindowsService/ nocase ascii wide

    condition:
        any of them
}
