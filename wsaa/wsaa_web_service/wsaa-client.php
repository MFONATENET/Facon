<?php

define ("CERT", "CertificadoPemX509.crt");       # The X.509 obtained from Seg. Inf.
#CERT = Archivo certificado que nos dió afip con extención .crt
define ("PRIVATEKEY", "MiClavePrivada2.key"); # The private key correspoding to CERT
#PRIVATEKEY clave privada nuestra, encriptada con clave eso se hace asi: openssl rsa -des -in MiClavePrivada.key -out MiClavePrivada2.key

define ("PASSPHRASE", "123456"); # The passphrase (if any) to sign
#Contraseña de la clave privada que se hace con el comando de arriba : openssl rsa -des -in MiClavePrivada.key -out MiClavePrivada2.key
# SERVICE: The WS service name you are asking a TA for

define ("SERVICE", "wsfe");
# WSAAURL: the URL to access WSAA, check for http or https and wsaa or wsaahomo
define ("WSAAURL", "https://wsaahomo.afip.gov.ar/ws/services/LoginCms");
# DESTINATIONDN must contain the WSAA dn, it must be exactly as follows, you
# should only change the "cn" portion, it should be "wsaahomo" for the testing
# WSAA or "wsaa" for the production WSAA.
define ("DESTINATIONDN", 
        "cn=wsaahomo,o=afip,c=ar,serialNumber=CUIT 33693450239");

#Configurar esto dependiendo de su Compu, poner el directorio completo xqe PHP se mmarea como yo con dos birras
define("TRA_DIR","C://xampp/htdocs/TRA.xml"); #Directorio donde se creará el TRA.xml
define("TMP_TRA_DIR", "C://xampp/htdocs/TRA.tmp"); #Directorio donde se creará el TRA.temporal
define("WSDL_WSAA","C://xampp/htdocs/wsaa.wsdl"); #Directorio donde ta el wsdl, recomendable q sea la misma carpeta
define("TA","C://xampp/htdocs/TA.xml"); #NUESTRO TICKET DE ACCESO :D

	
	//se arma el xml del TRA y se lo guarda en un archivo (TRA_DIR) 
	$TRA = new SimpleXMLElement(
    '<?xml version="1.0" encoding="UTF-8"?>' .
    '<loginTicketRequest version="1.0">'.
    '</loginTicketRequest>');
	$TRA->addChild( 'header' );
	$TRA->header->addChild( 'uniqueId', date('U') );
	$TRA->header->addChild( 'generationTime', date('c',date('U')-600) );
	$TRA->header->addChild( 'expirationTime', date('c',date('U')+600) );
	$TRA->addChild( 'service', SERVICE );
	$TRA->asXML( TRA_DIR ); //se graba el archivo

  //firmamos
	$STATUS = openssl_pkcs7_sign( TRA_DIR,TMP_TRA_DIR ,"file://".realpath(CERT),
	array("file://".realpath(PRIVATEKEY), PASSPHRASE),
	array(),
	!PKCS7_DETACHED
	);
			
	if (!$STATUS) 
	{
    {exit(CERT."-".PRIVATEKEY."-".PASSPHRASE."+".PKCS7_DETACHED);}
	}
	  
	$inf = fopen( TMP_TRA_DIR, "r");
	$w = 0;
	$CMS = "";
	  
	while(!feof($inf)) 
	{ 
	  $buffer = fgets($inf);
	  if ( $w++ >= 4 ) {
		$CMS.=$buffer;
		}
	}
		
	fclose($inf);
	unlink( TRA_DIR );
	unlink( TMP_TRA_DIR );
	  
	$client_wsaa = new SoapClient( WSDL_WSAA );
				  
	$results = $client_wsaa->loginCms(array('in0'=>$CMS));
	
	if (!file_put_contents( TA, $results->loginCmsReturn)){
		$error()->addError("NO_WRITE_TA",true);
	}  
	
	if (is_soap_fault($results))
	{
		$error()->addError("FALLO WSAA",true);
	}
		
	$ta_xml = simplexml_load_string($results->loginCmsReturn);	
	$TOKEN = $ta_xml->credentials->token;
	$SIGN = $ta_xml->credentials->sign;	
	echo "<p>TOKEN: ".$TOKEN ."</p>";
  echo "<br>";
  echo "<p>SIGN: ".$SIGN."</p>";
?>