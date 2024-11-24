rule sgn
{
    meta:
        description = "Detection patterns for the tool 'sgn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sgn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string1 = " Bruteforcing bad characters" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string2 = /\ssgn\.exe\s\-i\s/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string3 = " sgn_linux-arm64" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string4 = /\/sgn_linux\-amd64\.zip/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string5 = /\/sgn_linux\-arm64\.zip/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string6 = /\/sgn_windows\-amd64\.exe/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string7 = /\/sgn_windows\-amd64\.zip/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string8 = /\/sgn32\.exe/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string9 = /\/shellcode\.sgn/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string10 = "/tmp/ sgn -i /tmp/" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string11 = /\[\!\]\sThis\smay\stake\smore\stime\sto\sbruteforce\s/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string12 = /\[Author\:\-Ege\-Balc\?\-\]/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string13 = /\\sgn\.exe/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string14 = /\\sgn_linux\-amd64\.zip/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string15 = /\\sgn_windows\-amd64\.exe/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string16 = /\\sgn_windows\-amd64\.zip/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string17 = /\\sgn32\.exe/ nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string18 = "04645bb3fda6ec6c11bb22f4f053751ff7e07c145d4d8e1391651ac6a0ee851c" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string19 = "0c246202c0bc2e6db131df9e2bececcd1ed552a0d17dbb5da8552750d98bcdf1" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string20 = "1cdf39ef6ad31ac88c9e87a1ff987d56fc6101b1bea30b08239ccc6d8560b311" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string21 = "2301aca49d1e6f829a8859b41ea4decd4fb0451691733859018646bf047164f6" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string22 = "31113cca78db9828b1fb6c8f39cd227129049a64dc645fc6fa12cc9aec4eec56" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string23 = "362c03182899bbfcbd5502658dc569c82347a3eedccb7576a5e061a7a536171a" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string24 = "43cead8f26b98fad21e2e16e0d98da92e49606b347616c1a5eec5c0bcc492056" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string25 = "857a3380915575e74c40f0a36d92fdb55228a3c96476e90e902b440e921be6d1" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string26 = "89a674622f27cf3b03f04ee2da6bba953ea1843d0d1ffe4f62881f4ab4741caf" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string27 = "8b02540e34bb947d712daeffb713755041a7ee73f8bdb0f5a7a2fbf2d8113e1d" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string28 = "8ccf6166988aeda295d01347726b682bff22950b5549d7276737d3084022b292" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string29 = "98ca478259d56946281a780fe164c4415dd7dda9e4802b547b4622a8378b15b0" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string30 = "9e5f035ccefdbc02663184279025d1d84e2823a0340f6e027b55670987f0a42c" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string31 = "9f9619eb96a53d7166f5b853cbfe09c20d13d39e2b81cd14eb05f5240b42cce2" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string32 = "bc2a86638dcca2986c5099d1145af207a0e237815b29a9f727e39894c15ef4eb" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string33 = "c0d2859a5d2355d656eb7beb4c19608ab5c5d4407662bf0fd0e1f056f906f6ba" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string34 = "c59442ebadea15353f763e5e4ad6267d1c9acd9f40e3af728185b524478e4d66" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string35 = "docker pull egee/sgn" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string36 = "docker run -it egee/sgn" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string37 = "e11e118210b052c7d9ae1b8befde3254a6bf05ea82b8cca25d374aee39f064c4" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string38 = "e11e7c233271f76602b77312864c18c2daf0b4b86fd71422234776cb0b0ad04c" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string39 = "e1f8df267cad6116eb09bcb7047cae858b291630d86d9b5eb0879cb22cabc66c" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string40 = "EgeBalci/sgn" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string41 = "ICAgICAgIF9fICAgXyBfXyAgICAgICAgX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXyAKICBfX18gLyAvICAoXykgL19fX19fIF8vIC9fX19fIF8gIF9fXyBfX19fIF8gIF9fXyAgX19fIF8oXykKIChfLTwvIF8gXC8gLyAgJ18vIF8gYC8gX18vIF8gYC8gLyBfIGAvIF8gYC8gLyBfIFwvIF8gYC8gLyAKL19fXy9fLy9fL18vXy9cX1xcXyxfL1xfXy9cXyxfLyAgXF8sIC9cXyxfLyAvXy8vXy9cXyxfL18vICAKPT09PT09" nocase ascii wide
        // Description: polymorphic encoder used in  to obfuscate payloads
        // Reference: https://github.com/EgeBalci/sgn
        $string42 = "STARTING OBFUSCATED DECODER TESTS " nocase ascii wide

    condition:
        any of them
}
