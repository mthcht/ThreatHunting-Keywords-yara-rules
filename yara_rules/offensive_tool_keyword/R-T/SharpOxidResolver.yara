rule SharpOxidResolver
{
    meta:
        description = "Detection patterns for the tool 'SharpOxidResolver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpOxidResolver"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string1 = /\/SharpOxidResolver\.git/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string2 = /\/SharpOxidResolver\/releases\/download\// nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string3 = /\\OxidResolver\.exe/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string4 = /52BBA3C2\-A74E\-4096\-B65F\-B88C38F92120/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string5 = /6f2b8cefcfe918b0e6ae0449e03ee2bc0cfe9224dff57271478ebb5110965ffd/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string6 = /bb94573eaa965f3371451dcfbde19645354cfd7a8d18f2022d2497d182e72754/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string7 = /f9bfe5ec7093e75a2baeb578e87084aa65cd5bc5bd4ffaa4c3d4f9e051cd6a00/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string8 = /IOXIDResolver\.py/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string9 = /Nxy8P0NrG2AqvW5n5IAlaEbxDvev9hTfHiktFAhCDboW5oqsPSFu7\/xd6lTi43sXD4yfw\=/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string10 = /OxidResolver\.exe/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string11 = /S3cur3Th1sSh1t\/SharpOxidResolver/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string12 = /XjKVGK8ONDO9zVYwyGZBcz0pRjnm9eDj6vPpYOZqeAgr1n7aqBNgZPZolYoc\=/ nocase ascii wide

    condition:
        any of them
}
