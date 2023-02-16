<<<<<<< HEAD
# This is segments of main file "demo-encryptFileUsingCert.ps1". Segments listed here are intended for the party
# who is to decrypt a file
#
# step 1:   create a certificate (self-signed cert as example here), make private key exportable, non-protected
#           copy and save cert thumprint, which will be used to look up this cert from cert store

#           New-SelfSignedCertificate  -Subject "E=john.lan@bmo.com,CN=John Lan"  -CertStoreLocation "Cert:\CurrentUser\My"  -KeyExportPolicy Exportable  -Provider "Microsoft RSA SChannel Cryptographic Provider"


# step 2:   decrypt function 
#
Function Decrypt-Asymmetric
{
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
    $EncryptedBase64String,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Cert
)
    # Decrypts text using the private key
    # Assumes the certificate is in the LocalMachine\My (Personal) Store
    #$Cert = Get-ChildItem cert:\CurrentUser\My | where { $_.Thumbprint -eq $CertThumbprint }
    if($Cert) {
        $EncryptedByteArray = [Convert]::FromBase64String($EncryptedBase64String)
        # below version of decrypt overload no longer exists in PS 7. This works only PS5
        # $ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,$true))
        #
        #$ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        [byte[]]$ClearText = ($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        #returns a byte[] directly rather than a string
    }
    Else {Write-Error "Please provide a valid certificate!"}

    Return $ClearText
}

#region decrypting
#
# Step 4: Decrypt file as below
# 
#
$encyptedTxt = Get-Content "encrypted.txt"
write-host "`r`n-----------------------------"
write-host " Decrypting ..."
write-host "-----------------------------"
$cleartxt =[byte[]]@()
$certThumbprint= "FB70294DB58D82ACF92470F20B77306D5AE0F48D"
$Cert = Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertThumbprint }
    $count=0
foreach ($line in $encyptedTxt){
    $count++
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}

    #$cleartxt+= [System.Text.Encoding]::utf8.(Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
    $cleartxt +=  (Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
}
#$cleartxt | Set-Content "./decrypted.txt" -encoding UTF8 -Force -Confirm:$false 
#$cleartxt | Set-Content "./decrypted.txt" -asByteStream  -Force -Confirm:$false 
[System.IO.File]::WriteAllBytes("c:\temp\decrypted.txt", $cleartxt)

#
=======
# This is segments of main file "demo-encryptFileUsingCert.ps1". Segments listed here are intended for the party
# who is to decrypt a file
#
# step 1:   create a certificate (self-signed cert as example here), make private key exportable, non-protected
#           copy and save cert thumprint, which will be used to look up this cert from cert store

#           New-SelfSignedCertificate  -Subject "E=john.lan@bmo.com,CN=John Lan"  -CertStoreLocation "Cert:\CurrentUser\My"  -KeyExportPolicy Exportable  -Provider "Microsoft RSA SChannel Cryptographic Provider"


# step 2:   decrypt function 
#
Function Decrypt-Asymmetric
{
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
    $EncryptedBase64String,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Cert
)
    # Decrypts text using the private key
    # Assumes the certificate is in the LocalMachine\My (Personal) Store
    #$Cert = Get-ChildItem cert:\CurrentUser\My | where { $_.Thumbprint -eq $CertThumbprint }
    if($Cert) {
        $EncryptedByteArray = [Convert]::FromBase64String($EncryptedBase64String)
        # below version of decrypt overload no longer exists in PS 7. This works only PS5
        # $ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,$true))
        #
        #$ClearText = [System.Text.Encoding]::UTF8.GetString($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        [byte[]]$ClearText = ($Cert.PrivateKey.Decrypt($EncryptedByteArray,[System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        #returns a byte[] directly rather than a string
    }
    Else {Write-Error "Please provide a valid certificate!"}

    Return $ClearText
}

#region decrypting
#
# Step 4: Decrypt file as below
# 
#
$encyptedTxt = Get-Content "encrypted.txt"
write-host "`r`n-----------------------------"
write-host " Decrypting ..."
write-host "-----------------------------"
$cleartxt =[byte[]]@()
$certThumbprint= "FB70294DB58D82ACF92470F20B77306D5AE0F48D"
$Cert = Get-ChildItem cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertThumbprint }
    $count=0
foreach ($line in $encyptedTxt){
    $count++
    if ($count%59 -eq 0) {write-host "."}
    else {write-host "." -NoNewline}

    #$cleartxt+= [System.Text.Encoding]::utf8.(Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
    $cleartxt +=  (Decrypt-Asymmetric -EncryptedBase64String $line -Cert $cert)
}
#$cleartxt | Set-Content "./decrypted.txt" -encoding UTF8 -Force -Confirm:$false 
#$cleartxt | Set-Content "./decrypted.txt" -asByteStream  -Force -Confirm:$false 
[System.IO.File]::WriteAllBytes("c:\temp\decrypted.txt", $cleartxt)

#
>>>>>>> 30d82218ede3913643aa2482c7b7e6efc013fda6
#endregion decrypting