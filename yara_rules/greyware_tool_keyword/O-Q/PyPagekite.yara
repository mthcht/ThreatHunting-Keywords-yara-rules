rule PyPagekite
{
    meta:
        description = "Detection patterns for the tool 'PyPagekite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyPagekite"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string1 = /\sinstall\sxvnc4viewer\snetcat\-traditional\ssocat/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string2 = /\spagekite\.logging/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string3 = /\spagekite\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string4 = /\spagekite\-gtk\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string5 = /\"PageKite\ssystem\sservice\"/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string6 = /\/etc\/pagekite\.d/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string7 = /\/pagekite\-.{0,1000}\.log/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string8 = /\/pagekite\.log/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string9 = /\/pagekite\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string10 = /\/pagekite\-0\.3\.21\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string11 = /\/pagekite\-0\.4\.6a\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string12 = /\/pagekite\-0\.5\.6d\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string13 = /\/pagekite\-0\.5\.8a\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string14 = /\/pagekite\-gtk\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string15 = /\/pagekite\-tmp\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string16 = /\/PyPagekite\.git/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string17 = /\/PyPagekite\/tarball\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string18 = /\/PyPagekite\/zipball\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string19 = /\/var\/log\/pagekite\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string20 = /\/var\/run\/pagekite\.pid/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string21 = /\[PageKite\]\sRemote\sconnection\sclosed\!/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string22 = /\\pagekite\.cfg/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string23 = /\\pagekite\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string24 = /\\pagekite\-gtk\.py/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string25 = /23e8d0a95d5769ea14e4fd5eac6b5c111ce538e61b18492c21482afd015170eb/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string26 = /7270581d315cffb125f9ac64ebcb6622959c8e9f779b8a07808fd6929b0e746a/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string27 = /7dc50c28dc7c2fa9a6ea80df35c06bd649b17ae86d333e88b3bf242ac5690c98/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string28 = /b01db099512e344df190ee405619399c835b1d5522e2e6faa8e47b49418bab66/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string29 = /be8fc36ec0082bdb7d20a21ae7098899529bc9b9f6439b1496ca634395598d8a/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string30 = /bre\@pagekite\.net/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string31 = /c4ec5f4d04c44b7a1c8cf813435dbc66a541b450bbaca4d70ded985d6518e76a/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string32 = /f16d1b7d69bf4c2a9a7e737809dd930012f419e7b7977887226f0f6859367cc4/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string33 = /f2fd6676dba233df558278e6be42cd4c50a78a9c3f879db87acfc96607f41331/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string34 = /http\:\/\/.{0,1000}\.pagekite\.me/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string35 = /http\:\/\/up\.pagekite\.net\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string36 = /https\:\/\/.{0,1000}\.pagekite\.me/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string37 = /https\:\/\/pagekite\.net\/downloads\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string38 = /https\:\/\/pagekite\.net\/pk\/src\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string39 = /kitename\.pagekite\.me/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string40 = /pagekite\.httpd/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string41 = /pagekite\.py\s\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string42 = /pagekite\.py\s443\shttps\:\/\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string43 = /pagekite\.py\s80\shttp\:\/\// nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string44 = /pagekite\.py\s\-\-add\s/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string45 = /pagekite\.py\slocalhost\:/ nocase ascii wide
        // Description: This is pagekite.py a fast and reliable tool to make localhost servers visible to the public Internet.
        // Reference: https://github.com/pagekite/PyPagekite
        $string46 = /pagekite\/PyPagekite/ nocase ascii wide

    condition:
        any of them
}
