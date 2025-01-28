rule dumper2020
{
    meta:
        description = "Detection patterns for the tool 'dumper2020' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dumper2020"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string1 = /\/dumper2020\.git/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string2 = "/dumper2020_exe" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string3 = /\[\+\]\sCaptured\ssnapshot\sof\sLSASS\sprocess/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string4 = /\[\+\]\sSuccessfully\sopened\sLSASS\,\sPID\:\s/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string5 = /\\dumper2020_exe/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string6 = /\\dumper2020_exe\.cpp/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string7 = /\\dumper2020\-master/ nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string8 = "1b591c180e6c5221a81921e42b0256b62cec1f1af872624f5fd178d1ed7bd7c6" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string9 = "399399f17d32ec67656ef826a7efc16e48fb10f5b59da6b2d57feca3676a8190" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string10 = "423091502099d1c9adba971a42db7801b2e856c1fd5bed6f1ca70d0e39ca1a94" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string11 = "84A7E50E-B0F0-4B3D-98CD-F32CDB1EB8CA" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string12 = "a48708d0c27daec437448a1363e63b53d518cf00e60d701fe5f6292ffab1df00" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string13 = "B7355478-EEE0-46A7-807A-23CF0C5295AE" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string14 = "D8091ED0-5E78-4AF5-93EE-A5AA6E978430" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string15 = "ee30d8fb660ce3a25a8664c6214f2766a7099bdd78392009d961d22b7fd3ded2" nocase ascii wide
        // Description: Create a minidump of the LSASS process - attempts to neutralize all user-land API hooks before dumping LSASS
        // Reference: https://github.com/gitjdm/dumper2020
        $string16 = "gitjdm/dumper2020" nocase ascii wide

    condition:
        any of them
}
