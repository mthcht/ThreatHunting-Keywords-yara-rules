rule golang_c2
{
    meta:
        description = "Detection patterns for the tool 'golang_c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "golang_c2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string1 = /\/golang_c2\.git/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string2 = /cd\sgolang_c2/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string3 = /CREATE\sDATABASE\sC2\;/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string4 = /golang_c2\-master/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string5 = /m00zh33\/golang_c2/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string6 = /MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqKav9bmrSMSPwnxA3ul/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string7 = /MIIEpAIBAAKCAQEAqqKav9bmrSMSPwnxA3ulIleTPGiL9LGtdROute8ncU0HzPyL/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string8 = /mysql\s\-u.{0,1000}\s\-p\sc2\s\<\sc2_sample\.sql/ nocase ascii wide

    condition:
        any of them
}
