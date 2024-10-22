windows 上で esl を処理できるものが見つからなかったため、いくつかの候補から選択し、使えそうなことを確認しました。
もしかしたら使う人がいるかもしれないので、あげておきます。

# 使い方
元の [efitools](https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git) と同じです。
`efi-readesl` は `efi-readvar` のリスト出力が欲しかったため、おおむねニコイチして作成しました。

## powershell で efivars をダンプします。
```
Get-SecureBootUEFI PK -OutputFilePath '.\PK_dump'
Get-SecureBootUEFI KEK -OutputFilePath '.\KEK_dump'
Get-SecureBootUEFI db -OutputFilePath '.\db_dump'
Get-SecureBootUEFI dbx -OutputFilePath '.\dbx_dump'
```

## efi-readesl - ダンプの内容を確認
```
$ ./efi-readesl KEK_dump # 77fa9abd-0359-4d32-bd60-28f4e78f784b はマイクロソフトのGUID
KEK_dump: List 0, type X509
    Signature 0, size 1532, owner 77fa9abd-0359-4d32-bd60-28f4e78f784b
        Subject:
            C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation KEK CA 2011
        Issuer:
            C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation Third Party Marketplace Root
KEK_dump: List 1, type X509
    Signature 0, size 1478, owner 77fa9abd-0359-4d32-bd60-28f4e78f784b
        Subject:
            C=US, O=Microsoft Corporation, CN=Microsoft Corporation KEK 2K CA 2023
        Issuer:
            C=US, O=Microsoft Corporation, CN=Microsoft RSA Devices Root CA 2021
```

## sig-list-to-certs - ダンプに含まれるx509証明書などの取得
```
$ ./sig-list-to-certs.exe KEK_dump KEK_dump # KEK_dump-0.der みたいなファイルができます。
X509 Header sls=1560, header=0, sig=1516
file KEK_dump-0.der: Guid 77fa9abd-0359-4d32-bd60-28f4e78f784b
Written 1516 bytes
X509 Header sls=1506, header=0, sig=1462
file KEK_dump-1.der: Guid 77fa9abd-0359-4d32-bd60-28f4e78f784b
Written 1462 bytes
```

## cert-to-efi-sig-list - x509証明書（pem形式）を esl に変換
```
$ openssl x509 -inform der -in KEK_dump-0.der -out KEK_dump-0.pem
$ openssl x509 -inform der -in KEK_dump-1.der -out KEK_dump-1.pem
$ ./cert-to-efi-sig-list -g 77fa9abd-0359-4d32-bd60-28f4e78f784b KEK_dump-0.pem KEK_dump-0.esl
$ ./cert-to-efi-sig-list -g 77fa9abd-0359-4d32-bd60-28f4e78f784b KEK_dump-1.pem KEK_dump-1.esl
$ cat KEK_dump-*.esl >KEK_dump.esl # これでダンプと同じものができるはずです。
```

# ビルド
* ビルド環境 [MSYS2](https://www.msys2.org/) ucrt64
* [gnu-efi](https://sourceforge.net/projects/gnu-efi/) のヘッダファイルを `include\efi` に配置。
```
cd efitools
make sig-list-to-certs cert-to-efi-sig-list efi-readesl
```

# enroll メモ（それぞれの変数に対応する証明書が必要です）
secureboot がセットアップモードな場合、PK を登録すると変更する際に対応する証明書が必要になるので、PK の登録は最後がおすすめです。
逆に言えば PK さえ自前のものを登録しておけばどうとでもできます。
```
$SIG_OWNER_GUID = '00000000-0000-0000-0000-000000000000'
$DATE_TIME = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
Set-SecurebootUEFI -Name dbx -ContentFilePath .\dbxDefault_dump -Time $DATE_TIME
Set-SecurebootUEFI -Name db -ContentFilePath .\dbDefault_dump -Time $DATE_TIME
Set-SecurebootUEFI -Name KEK -ContentFilePath .\KEKDefault_dump -Time $DATE_TIME
$PKobject = ( Format-SecureBootUEFI -Name PK -SignatureOwner $SIG_OWNER_GUID -Time $DATE_TIME -CertificateFilePath .\pkcert.der -FormatWithCert -SignableFilePath PK.esl )
Invoke-Expression "path\signtool.exe sign /fd sha256 /p7 . /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /n 'UEFI Platform Key Certificate' PK.esl"
$PKobject | Set-SecurebootUEFI -SignedFilePath PK.esl.p7
```

KEK に [Microsoft Corporation KEK 2K CA 2023](https://go.microsoft.com/fwlink/?linkid=2239775) を追加する。
```
$MS_SIG_OWNER_GUID = '77fa9abd-0359-4d32-bd60-28f4e78f784b'
$DATE_TIME = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$KEKobject = ( Format-SecureBootUEFI -Name KEK -SignatureOwner $MS_SIG_OWNER_GUID -Time $DATE_TIME -CertificateFilePath '.\microsoft corporation kek 2k ca 2023.crt' -AppendWrite -FormatWithCert -SignableFilePath KEK.esl )
Invoke-Expression "path\signtool.exe sign /fd sha256 /p7 . /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /n 'UEFI Platform Key Certificate' KEK.esl"
$KEKobject | Set-SecurebootUEFI -SignedFilePath KEK.esl.p7

```

削除もできます。
```
$DATE_TIME = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$PKobject = ( Format-SecureBootUEFI -Name PK -Delete -Time $DATE_TIME -SignableFilePath PK.esl )
Invoke-Expression "path\signtool.exe sign /fd sha256 /p7 . /p7co 1.2.840.113549.1.7.1 /p7ce DetachedSignedData /a /n 'UEFI Platform Key Certificate' PK.esl"
$PKobject | Set-SecurebootUEFI -SignedFilePath PK.esl.p7
```

# 参考情報など
* [Windows セキュア ブート キーの作成と管理のガイダンス | Microsoft Learn](https://learn.microsoft.com/ja-jp/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11)
* [Unified Extensible Firmware Interface/セキュアブート - ArchWiki](https://wiki.archlinux.jp/index.php/Unified_Extensible_Firmware_Interface/%E3%82%BB%E3%82%AD%E3%83%A5%E3%82%A2%E3%83%96%E3%83%BC%E3%83%88)
* [User:Sakaki/Sakaki's EFI Install Guide/Configuring Secure Boot - Gentoo Wiki](https://wiki.gentoo.org/wiki/User:Sakaki/Sakaki%27s_EFI_Install_Guide/Configuring_Secure_Boot)
