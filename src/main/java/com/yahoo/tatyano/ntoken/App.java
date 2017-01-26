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
            String rsaPrivateKeyFile = null;
            String domainName = null;
            String serviceName = null;
            String NTokenFile = null;
            String authorizedServiceName = null;
            String keyId = "0";
            String authorizedServiceKeyId = "0";
            long tokenTimeout = 3600;
            String host = null;

            // setup the key identifier that the corresponding public key
            // has been registered in ZMS, and set the timeout to be 1 hour
            rsaPrivateKeyFile = args[0];
            domainName = args[1];
            serviceName = args[2];
            if (args.length > 3) {
                NTokenFile = args[3];
                authorizedServiceName = args[4];
            }

            // we're going to extract our private key from a given file
            File rsaPrivateKey = new File(rsaPrivateKeyFile);
            PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);

            PrincipalToken token = new PrincipalToken.Builder("S1", domainName, serviceName)
                .expirationWindow(tokenTimeout).host(host).keyId(keyId).authorizedServices(Arrays.asList(serviceName)).build();
            token.sign(privateKey);
            System.out.println( "Service-Token: "+token.getSignedToken() );
            
            if (NTokenFile != null && authorizedServiceName != null) {
                String ntoken = new String(Files.readAllBytes(Paths.get(NTokenFile))).replaceAll("\n", "");;
                PrincipalToken userToken = new PrincipalToken(ntoken);
                System.out.println( "User-Token: "+NTokenFile );
                System.out.println( "User-Token: "+ntoken );
                System.out.println( "User-Token: "+userToken.getSignedToken() );
                
                userToken.signForAuthorizedService(authorizedServiceName, authorizedServiceKeyId, privateKey);
                System.out.println( "Signed User-Token: "+userToken.getSignedToken() );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
