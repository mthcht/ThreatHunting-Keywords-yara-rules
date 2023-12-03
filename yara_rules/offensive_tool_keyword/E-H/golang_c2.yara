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
        $string1 = /.{0,1000}\/golang_c2\.git.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string2 = /.{0,1000}cd\sgolang_c2.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string3 = /.{0,1000}CREATE\sDATABASE\sC2\;.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string4 = /.{0,1000}golang_c2\-master.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string5 = /.{0,1000}m00zh33\/golang_c2.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string6 = /.{0,1000}MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqKav9bmrSMSPwnxA3ul.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string7 = /.{0,1000}MIIEpAIBAAKCAQEAqqKav9bmrSMSPwnxA3ulIleTPGiL9LGtdROute8ncU0HzPyL.{0,1000}/ nocase ascii wide
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string8 = /.{0,1000}mysql\s\-u.{0,1000}\s\-p\sc2\s\<\sc2_sample\.sql.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
