rule saint
{
    meta:
        description = "Detection patterns for the tool 'saint' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saint"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string1 = /\%appdata\%\\\(s\)AINT/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string2 = /\/sAINT\.git/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string3 = /\/sAINT\-master\.zip/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string4 = /\:\:\sRemove\s\(s\)AINT\sfolder/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string5 = /\\\(s\)AINT\\Cam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string6 = /\\\(s\)AINT\\Logs/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string7 = /\\\(s\)AINT\\saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string8 = /\\\(s\)AINT\\Screenshot/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string9 = /\\\\saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string10 = /\\AppData\\Local\\Temp\\factura\.exe/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string11 = /\\sAINT\-master\.zip/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string12 = /\]\sEnable\sPersistence\s\(Y\/n\)\:\s/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string13 = /\]\sYou\swould\slike\sto\sgenerate\s\.EXE\susing\slauch4j\?\s\(y\/n\)\:/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string14 = /AppData\\Roaming\\\(s\)AINT/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string15 = /import\sorg\.jnativehook\.keyboard\.NativeKeyListener/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string16 = /import\ssaint\.email\.SendEmail/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string17 = /import\ssaint\.screenshot\.Screenshot/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string18 = /import\ssaint\.webcam\.Cam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string19 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string20 = /java\s\-jar\ssAINT\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string21 = /Keylogger\.java/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string22 = /launch4j\slaunch4j\/sAINT\.xml/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string23 = /package\ssaint\.keylogger/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string24 = /package\ssaint\.webcam/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string25 = /public\sclass\sKeylogger/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string26 = /REG\sADD\sHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\s\/V.{0,1000}saint\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string27 = /reg\sdelete\sHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\sSecurity\s\/f/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string28 = /sAINT.{0,1000}launch4j\.tar\.xz/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string29 = /sAINT\\lib\\activation\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string30 = /saint\-1\.0\-jar\-with\-dependencies\.exe/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string31 = /saint\-1\.0\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string32 = /tiagorlampert\/sAINT/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string33 = /ui\\sAINT\.java/ nocase ascii wide
        // Description: (s)AINT is a Spyware Generator for Windows systems written in Java
        // Reference: https://github.com/tiagorlampert/sAINT
        $string34 = /webcam\-capture\-0\.3\.10\.jar/ nocase ascii wide

    condition:
        any of them
}
