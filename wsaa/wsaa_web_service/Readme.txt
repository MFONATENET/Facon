Para hacer este ArtAttack necesitas!

-CertificadoPemX509.crt: Certificado que nos da afip, que te lo dan en formato X509, en extensión .crt 

- MiClavePrivada2.key: clave privada de la maquina, o del server lo hice en .key porque asi estaba el ejemplo, también a esta clave le puse clave de la siguiente manera: openssl rsa -des -in MiClavePrivada.key -out MiClavePrivada2.key
desp de eso te pide la contraseña.
"PASSPHRASE" = Password puesto arriba 

#Configurar esto dependiendo de su Compu, poner el directorio completo xqe PHP se mmarea como yo con dos birras
define("TRA_DIR","C://xampp/htdocs/TRA.xml"); #Directorio donde se creará el TRA.xml
define("TMP_TRA_DIR", "C://xampp/htdocs/TRA.tmp"); #Directorio donde se creará el TRA.temporal
define("WSDL_WSAA","C://xampp/htdocs/wsaa.wsdl"); #Directorio donde ta el wsdl, recomendable q sea la misma carpeta
define("TA","C://xampp/htdocs/TA.xml"); #NUESTRO TICKET DE ACCESO :D