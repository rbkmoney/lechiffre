# Le Chiffre



 ________________             _______________             ________
|                |           |               | encrypt   |        |
| VersionedToken | --------> | Thrift Binary | --------> | Binary |
|                |           |               |           |        |
 ----------------             ---------------             --------

 ________              _______________               ________________
|        |  decrypt   |               |             |                |
| Binary | ---------> | Thrift Binary | ----------> | VersionedToken |
|        |            |               |             |                |
 --------              ---------------               ----------------


## Создание JWK(using step-cli)

$ step crypto jwk create jwk_oct.pub.json jwk.json -kty=oct -size=32 -use=enc -alg=dir -kid=123 -password-file=jwk.password
