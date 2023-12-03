rule openbullet
{
    meta:
        description = "Detection patterns for the tool 'openbullet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openbullet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string1 = /.{0,1000}\/openbullet\.git.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string2 = /.{0,1000}\/OpenBullet2\.git.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string3 = /.{0,1000}0B6D8B01\-861E\-4CAF\-B1C9\-6670884381DB.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string4 = /.{0,1000}99E40E7F\-00A4\-4FB1\-9441\-B05A56C47C08.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string5 = /.{0,1000}C8482002\-F594\-4C28\-9C46\-960B036540A8.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string6 = /.{0,1000}OpenBullet\.csproj.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string7 = /.{0,1000}OpenBullet\.exe.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string8 = /.{0,1000}OpenBullet\.pdb.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string9 = /.{0,1000}OpenBullet\.sln.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string10 = /.{0,1000}OpenBullet\.zip.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string11 = /.{0,1000}openbullet\/openbullet.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string12 = /.{0,1000}OpenBullet2\.Console\.zip.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string13 = /.{0,1000}OpenBullet2\.Native\.exe.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string14 = /.{0,1000}OpenBullet2\.Native\.zip.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string15 = /.{0,1000}OpenBullet2\.zip.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string16 = /.{0,1000}openbullet2:latest.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string17 = /.{0,1000}OpenBullet2\-master.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string18 = /.{0,1000}OpenBulletApp\.cs.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string19 = /.{0,1000}OpenBulletCLI\.csproj.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string20 = /.{0,1000}OpenBulletCLI\.exe.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/openbullet
        $string21 = /.{0,1000}openbullet\-master.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string22 = /.{0,1000}Welcome\sto\sOpenBullet\s2.{0,1000}/ nocase ascii wide
        // Description: The OpenBullet web testing application.
        // Reference: https://github.com/openbullet/OpenBullet2
        $string23 = /.{0,1000}Write\-Output\s127\.0\.0\.1:1111.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
