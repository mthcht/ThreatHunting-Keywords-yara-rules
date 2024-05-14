rule Luna_Grabber
{
    meta:
        description = "Detection patterns for the tool 'Luna-Grabber' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Luna-Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string1 = /\sDisable_defender\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string2 = /\sLuna\sGrabber\sBuilder/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string3 = /\ssigthief\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string4 = /\.\/Obfuscated_.{0,1000}\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string5 = /\/Disable_defender\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string6 = /\/Kill_protector\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string7 = /\/luna\.log/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string8 = /\/Luna\-Grabber\.git/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string9 = /\/Luna\-Grabber\/releases\/download\// nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string10 = /\/Luna\-Grabber\/tarball\// nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string11 = /\/Luna\-Grabber\/zipball/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string12 = /\/Luna\-Grabber\-Injection\/main/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string13 = /\/sigthief\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string14 = /\/tools\/obfuscation\.py\s\-i\s/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string15 = /\\Disable_defender\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string16 = /\\Kill_protector\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string17 = /\\luna\.log/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string18 = /\\Luna\-Logged\-.{0,1000}\.zip/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string19 = /\\roblox\scookies\.txt/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string20 = /\\sigthief\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string21 = /1119pepesneakyevil/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string22 = /505bb78684c53f9fb96c92611bbd7ed7096c166f3621fc602b4f0402e0605621/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string23 = /5ac7b2c9c03ec6be6c8e0ea6ffd0b9ca0c69a8f2472d3e183780bfc6f86fc7f6/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string24 = /6f7204e9f37025c754fd990061bda4246aa63d13e4f9fe951c7a2871c2ecf5f5/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string25 = /9dc2d1ac93b43a6f3450e6d99201dfa4b7e75e8872d97b6cc90e455201ff0c83/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string26 = /BlankOBF\sv2\:\sObfuscates\sPython\scode\sto\smake\sit\sunreadable\sand\shard\sto\sreverse/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string27 = /c2a640190d6567ec2b613cb2f3a37496a4df5450c577e4326b13457f69ba7160/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string28 = /caadd01f003376a0d92f5bcc416a1702802c5c1072907644e29f39fb2c6c513c/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string29 = /d71c3ea3ec686a8c080f8310b25cfe4696773a06fe151d03eb9a69de9147abcb/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string30 = /e2c3b2d10ba4db5f13e05de8197818f8ce94da878b5eba6c82a7feb73340b538/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string31 = /e6be8653e8355627406150a70434675aaad1cab5dbe2116237df5bf2ff7f4b45/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string32 = /f34b6048a755da93e66d8335d69d98eecc76dcb4ea0e7b816dc9af12ba8b6b22/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string33 = /f4d042d26b74e99f7442cbd0b9e3587f512fc6367f5759d6451d28856526db15/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string34 = /Luna\sGrabber\s\|\sCreated\sBy\sSmug/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string35 = /Luna\sGrabber\sBuilder\s\-\sRunning\son\sv/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string36 = /SELECT\shost_key\,\sname\,\spath\,\sencrypted_value\,\sexpires_utc\sFROM\scookies/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string37 = /SELECT\sname_on_card\,\sexpiration_month\,\sexpiration_year\,\scard_number_encrypted\sFROM\scredit_cards/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string38 = /SELECT\sorigin_url\,\susername_value\,\spassword_value\sFROM\slogins/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string39 = /Smug246\/Luna\-Grabber/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string40 = /Successfully\sobfuscated\sfile\:\s.{0,1000}\.py/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string41 = /You\sfinally\sbroke\sthrough\sBlankOBF\sv2\;\sGive\syourself\sa\spat\son\syour\sback\!/ nocase ascii wide
        // Description: discord token grabber made in python
        // Reference: https://github.com/Smug246/Luna-Grabber
        $string42 = /Your\sversion\sof\sLuna\sToken\sGrabber\sis\soutdated\!/ nocase ascii wide

    condition:
        any of them
}
