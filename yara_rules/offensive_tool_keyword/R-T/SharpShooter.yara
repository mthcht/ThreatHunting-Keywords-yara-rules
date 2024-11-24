rule SharpShooter
{
    meta:
        description = "Detection patterns for the tool 'SharpShooter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShooter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string1 = /\samsikiller\.py/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string2 = " --com xslremote --awlurl " nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string3 = /\s\-\-dotnetver\s.{0,1000}\s\-\-payload\s.{0,1000}\s\-\-sandbox\s/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string4 = /\s\-\-payload\s.{0,1000}\s\-\-output\s.{0,1000}\s\-\-rawscfile\s.{0,1000}\s\-\-smuggle\s/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string5 = /\s\-\-rawscfile\s\.\/x86payload\.bin/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string6 = " --smuggle --template mcafee --com " nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string7 = /\s\-\-stageless\s\-\-dotnetver\s.{0,1000}\s\-\-payload\s/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string8 = /\/amsikiller\.py/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string9 = /\/SharpShooter\.git/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string10 = /\\amsikiller\.py/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string11 = /\\SharpShooter\./ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string12 = /\\sharpshooter\.js/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string13 = /\\sharpshooter\.vba/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string14 = /\\sharpshooter\.vbs/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string15 = /\\SharpShooter\-main/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string16 = /\\sharpshooterv4\.js/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string17 = /\\sharpshooterv4\.vba/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string18 = /\\sharpshooterv4\.vbs/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string19 = /\\stageless\.vba/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string20 = /\\stageless\.vbs/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string21 = /\\stagelessv4\.vba/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string22 = /\\stagelessv4\.vbs/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string23 = "23f017c0041a2164abfe06a03e3ad5b32e002e46d513f314632ed38280de8b14" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string24 = "286a68fb3a355b790f127b74edb0d084749960ee7b1d9e66c1eb094c14733631" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string25 = "2d2e0ad0b515712ae445a179701ae0e61d759498bea45c9431ae93c1469e1172" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string26 = "39556e3779ee1fc2a06c32eff48acd03a01aa0b59bac075ad1457b65a14b3911" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string27 = "51479ff32cd7f2520a0b252fa3731361c3cc3288d6b0f7831b91a208cd91aaa3" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string28 = "56598F1C-6D88-4994-A392-AF337ABE5777" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string29 = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string30 = "AG8AbwB0AGUAcgBBAHMAcwBlAG0AYgBsAHkAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIA" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string31 = "AQ0AAAAEAAAACRcAAAAJBgAAAAkWAAAABhoAAAAnU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkg" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string32 = "AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string33 = /create_awl_payload\(/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string34 = /create_com_stager\(/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string35 = "dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string36 = "LgBkAGwAbAAAAAAASgAVAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAABTAGgAYQByAHAAUwBo" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string37 = "Macro payload cannot be smuggled" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string38 = "mdsecactivebreach/SharpShooter" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string39 = "SharpShooter" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string40 = /SharpShooter\.py/ nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string41 = "Stageless payloads require the --rawscfile argument" nocase ascii wide
        // Description: Payload Generation Framework
        // Reference: https://github.com/mdsecactivebreach/SharpShooter
        $string42 = "ZXMARGVidWdnaW5nTW9kZXMAZ2V0X1JlZmVyZW5jZWRBc3NlbWJsaWVzAEdldElQR2xvYmFsUHJv" nocase ascii wide

    condition:
        any of them
}
