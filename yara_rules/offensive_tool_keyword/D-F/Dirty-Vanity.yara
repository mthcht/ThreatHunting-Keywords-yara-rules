rule Dirty_Vanity
{
    meta:
        description = "Detection patterns for the tool 'Dirty-Vanity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dirty-Vanity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string1 = /\#include\s\\"DirtyVanity\.h\\"/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string2 = /\/Dirty\-Vanity\.git/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string3 = /\/k\smsg\s.{0,1000}\sHello\sfrom\sDirty\sVanity/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string4 = /\/k\smsg\s.{0,1000}\sHello\sfrom\sTam\.Men/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string5 = /\/vanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string6 = /\[\+\]\sNo\sPID\sprovided\,\screating\sa\snew\scalc\.exe\sprocess\sand\susing\sits\sPID/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string7 = /\[\+\]\sSuccesfuly\swrote\sshellcode\sto\svictim\.\sabout\sto\sstart\sthe\sMirroring/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string8 = /\[\+\]\sUSAGE\:\sDirtyVanity\s/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string9 = /\\DirtyVanity\.cpp/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string10 = /\\DirtyVanity\.sln/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string11 = /\\vanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string12 = "2C809982-78A1-4F1C-B0E8-C957C93B242F" nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string13 = "2d837b6c7343aec8123077db07d3fb8f9f7e44c5b108bf713380b17dac7569b9" nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string14 = "53891DF6-3F6D-DE4B-A8CD-D89E94D0C8CD" nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string15 = "deepinstinct/Dirty-Vanity" nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string16 = /DirtyVanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string17 = "e977ee0a5a2f0063f34b0b744b0753e65990e9467843b0dec3c281a6d4a2e009" nocase ascii wide

    condition:
        any of them
}
