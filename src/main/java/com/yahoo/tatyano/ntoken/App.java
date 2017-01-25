package com.yahoo.tatyano.ntoken;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Arrays;

import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        try {
            // setup the key identifier that the corresponding public key
            // has been registered in ZMS, and set the timeout to be 1 hour
            String rsaPrivateKeyFile = args[0];
            String NTokenFile = args[1];
            String domainName = args[2];
            String serviceName = args[3];
            String authorizedServiceName = args[4];
            String keyId = "0";
            String authorizedServiceKeyId = "0";
            long tokenTimeout = 3600;
            String host = null;

            // we're going to extract our private key from a given file
            File rsaPrivateKey = new File(rsaPrivateKeyFile);
            PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);

            PrincipalToken token = new PrincipalToken.Builder("S1", domainName, serviceName)
                .expirationWindow(tokenTimeout).host(host).keyId(keyId).authorizedServices(Arrays.asList(serviceName)).build();
            token.sign(privateKey);
            System.out.println( "Service-Token: "+token.getSignedToken() );
            
            String ntoken = new String(Files.readAllBytes(Paths.get(NTokenFile))).replaceAll("\n", "");;
            PrincipalToken userToken = new PrincipalToken(ntoken);
            System.out.println( "User-Token: "+NTokenFile );
            System.out.println( "User-Token: "+ntoken );
            System.out.println( "User-Token: "+userToken.getSignedToken() );
            
            userToken.signForAuthorizedService(authorizedServiceName, authorizedServiceKeyId, privateKey);
            System.out.println( "Signed User-Token: "+userToken.getSignedToken() );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
