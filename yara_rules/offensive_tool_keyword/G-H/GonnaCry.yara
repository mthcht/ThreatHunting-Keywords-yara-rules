rule GonnaCry
{
    meta:
        description = "Detection patterns for the tool 'GonnaCry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GonnaCry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string1 = "/bin/gonnacry"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string2 = /\/GonnaCry\.git/ nocase ascii wide
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string3 = "/home/tarcisio/teste" nocase ascii wide
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string4 = "2fb873b8303300b7a5df14c5bf0271118343bc20c3f36208148b5e4966c47a36"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string5 = "3203466ca861519109bd827fc930867acd7062c4f2171eebd4b3c21f1632454b"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string6 = "3655e26bfd9900a39da92af0cbd8ac57decf67a6f31680db406e8b534c6a94e4"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string7 = "43565fef63fccc1c7ad4781870b96ac61b93974ac1495700ee461621ed6b432c"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string8 = "45480e4a4de392608ab151ba8c1586f5a65319c976fbfa0f9f5f0ab72bad76df"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string9 = "4fbeeeeda8c0b7858a26a16fc65709b3a3c08d309032602574f4f7438964612f"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string10 = "5a4dd116f4daaedde86acb94e662e4bd4840fdccad203f9888bdab0390ae6954"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string11 = "5e2c017817ac29d2717628ba6fd14b3be13ada1c74afd77ee80c1312a6f5586b"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string12 = "6df4c790fd104f1a9e2e68cf8411c39280df7c4b1f2ada6ab1836546645d6865"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string13 = "7c20345b30b2db97967812965d5a90ba34424cc481d073914d016e2541494f6f"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string14 = "7c7b8879594486833d1c8baf05f6377ab7cb7a9b3a285ea159f25760b2d4070c"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string15 = "7fd9f158c430a2d17fcd8fac698cfe71ef4f6530c2df824247c651acd6a1f03e"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string16 = "a1b8bf87544be53073f60ca03c4e1df5361cc7e54b4d32b30e55ba8e1f38f457"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string17 = "a611f2d2b08ad8bffc69e578d6a99302114002e143b80f0bde003db299822b84"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string18 = "b01d196f7d55bb7eb688d1f72d3d238ac95a4822e6712e197f816245d6eadf75"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string19 = "b3b1853594a5c1c6ec5d8338b4a22daf42b8ccdf2c10b3966a8db3c46377b52a"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string20 = "befbdaf08e78ab9ee8e418215b4a22102576ab472c73324ec59a6b890be1b5b3"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string21 = "cb6759a0fccc69211687c11da0831532c127e7657eb74bc9ee3c86ad08097935"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string22 = "cc762d44919d522ac0820401f1cdbc983865a9132728587f1dd47182d093fc88"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string23 = "ccde1cee6a570b7e54c7e02228a65a3a25a968d163314d072104fe0113ae5f7b"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string24 = "d1ac1450eece96c89d0721fb21e39d299b4157ea35b2d4ed8b91fbc766974101"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string25 = "d2c8ef54b087ba42e9745f210cdc9ae431a8092ca2c2c7878a2b8329d77cb447"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string26 = "d617ba8cc034438b50e1b4afbe5ae7baa244176f01e67d6be160d1e5428537e2"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string27 = "dd15d1c8a833d00505cfb93910c5af2d98e78809c4295fd39a8bd656230205e1"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string28 = "e71047e3345b665cafc213f16980ff93ff6a31ed242b32ab08884eb8298ea623"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string29 = "e920909e0910ab0c7aaf3e402f997d6e05e3a843ef9504b2c97389e76cb38e76"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string30 = "fc5174e15f2021575ed3f96a79a316e92146e3869020d00220fb608497b422a0"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string31 = "pidof gonnacry" nocase ascii wide
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string32 = "pyinstaller -F --clean GonnaCry"
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string33 = /tarcisio_marinho09\@hotmail\.com/
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string34 = "tarcisio-marinho/GonnaCry" nocase ascii wide
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string35 = /your_encrypted_files\.txt/

    condition:
        any of them
}
