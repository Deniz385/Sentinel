rule Suspicious_Keywords {
    meta:
        description = "Şüpheli kelimeler içeren dosya"
        author = "Sentinel DLP"
    strings:
        $a = "hack" nocase
        $b = "virus" nocase
        $c = "backdoor" nocase
        $d = "cmd.exe" nocase
    condition:
        any of them
}

rule Fake_Malware_Signature {
    meta:
        description = "Test amaçlı sahte malware imzası"
    strings:
        // EICAR test dosyasının başlangıcı gibi basit bir imza
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}