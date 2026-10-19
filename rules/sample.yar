/*
 * Sentinel YARA kuralları
 *
 * Bu dosya v3.0'da depoda duruyordu ama hiçbir kod onu okumuyordu.
 * Artık `sentinel/yara_engine.py` tarafından derlenip çalıştırılır
 * (yara-python kurulu olduğunda: pip install 'sentinel-dlp[yara]').
 *
 * `meta.severity` alanı Sentinel'in önem derecesi kademelerinden biri
 * olmalıdır: info | low | medium | high | critical
 */

rule Sentinel_EICAR_Test_File
{
    meta:
        description = "EICAR standart antivirüs test dosyası"
        severity = "medium"
        author = "Sentinel DLP"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        // Dizge parça parça yazılır; aksi hâlde bu kural dosyasının
        // kendisi antivirüs tarafından karantinaya alınır.
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $a
}

rule Sentinel_Credential_Dump
{
    meta:
        description = "Kimlik bilgisi dökümü (credential dump) kalıbı"
        severity = "critical"
        author = "Sentinel DLP"

    strings:
        $shadow = /root:[\$!*][^\n:]{0,200}:\d{5}:/
        $sam    = "SAM\\Domains\\Account\\Users" nocase
        $ntlm   = /[a-f0-9]{32}:[a-f0-9]{32}/
        $mimi   = "sekurlsa::logonpasswords" nocase

    condition:
        any of them
}

rule Sentinel_Private_Key_Block
{
    meta:
        description = "Özel anahtar (private key) bloğu"
        severity = "critical"
        author = "Sentinel DLP"

    strings:
        $rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $ec      = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pgp     = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $pkcs8   = "-----BEGIN PRIVATE KEY-----"

    condition:
        any of them
}

rule Sentinel_Webshell_Indicator
{
    meta:
        description = "Web kabuğu (webshell) göstergesi: kullanıcı girdisinden komut çalıştırma"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $php_eval   = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php_system = /(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $asp_eval   = /eval\s*\(\s*Request/ nocase
        $py_exec    = /exec\s*\(\s*request\./ nocase

    condition:
        any of them
}

rule Sentinel_Database_Dump
{
    meta:
        description = "Veritabanı dökümü — tablo yapısı ve toplu INSERT"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $mysqldump = "-- MySQL dump" nocase
        $pgdump    = "-- PostgreSQL database dump" nocase
        $create    = /CREATE TABLE `?(users?|customers?|musteri|kullanici|members?)`?/ nocase
        $insert    = /INSERT INTO `?(users?|customers?|musteri|kullanici)`?/ nocase

    condition:
        ($mysqldump or $pgdump) or (#create > 0 and #insert > 2)
}

rule Sentinel_Exfiltration_Script
{
    meta:
        description = "Veri sızdırma betiği: dosya okuyup uzak adrese gönderme"
        severity = "high"
        author = "Sentinel DLP"

    strings:
        $curl_post  = /curl\s+(-[A-Za-z]+\s+)*(-X\s*POST|--data|-d\s+@)/ nocase
        $requests   = "requests.post(" nocase
        $read_doc   = /(Documents|Belgeler|Desktop|Masa.st|\.ssh|\.aws)/ nocase
        $archive    = /(zipfile|tarfile|7z|rar)\s*[\.\(]/ nocase

    condition:
        ($curl_post or $requests) and $read_doc and $archive
}
