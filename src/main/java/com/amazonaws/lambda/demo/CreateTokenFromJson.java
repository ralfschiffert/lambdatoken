package com.amazonaws.lambda.demo;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.impl.DefaultClock;
import java.security.Key;
import org.json.simple.parser.JSONParser;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;


public class CreateTokenFromJson implements RequestHandler<Object, String> {
	
	private static String DECRYPTED_KEY = decryptKey();
	
	private static String decryptKey() {
        // System.out.println("Decrypting key");
        byte[] encryptedKey = Base64.decode(System.getenv("secret"));

        AWSKMS client = AWSKMSClientBuilder.defaultClient();

        DecryptRequest request = new DecryptRequest()
                .withCiphertextBlob(ByteBuffer.wrap(encryptedKey));

        ByteBuffer plainTextKey = client.decrypt(request).getPlaintext();
        return new String(plainTextKey.array(), Charset.forName("UTF-8"));
    }
	
	
	

	@Override
	public String handleRequest(Object input, Context context) {
		context.getLogger().log("Input: " + input);

		ObjectMapper mapper = new ObjectMapper();
		String first_name = "N.A";
		String last_name = "N.A.";
		String email = "N.A.";
		String username = "N.A.";

		try {

			JsonFactory factory = new JsonFactory();
			JsonParser parser = factory.createParser(mapper.writeValueAsString(input));
			JsonNode root = mapper.readTree(parser);
			first_name = root.path("first_name").asText();
			last_name = root.path("last_name").asText();
			email = root.path("email").asText();
			username = root.path("username").asText();
		} catch (JsonProcessingException e) {
			context.getLogger().log("could not process JSON input");
		} catch (IOException e) {
			context.getLogger().log("could not process JSON input");
		}
		
		
		Map<String, Object> myClaims = new HashMap<String, Object>();
		myClaims.put("first_name", first_name);
		myClaims.put("last_name", last_name);
		myClaims.put("email", email);
		myClaims.put("username", username);
		
		
		long nowMillis = System.currentTimeMillis();
	    Date now = new Date(nowMillis);
	    Date soon = new Date(nowMillis + 24*7*3600*1000);
	    
	   
	    byte[] b = null;
	    
	    try {
	    	// b = "52ad2636-53b3-11e7-abe7-73d47c3d85fe".getBytes("UTF-8");
	    	b = DECRYPTED_KEY.getBytes("UTF-8");
	    } 
	    catch ( UnsupportedEncodingException e ) {
	    	context.getLogger().log("cannot work with suppliled secret key");
	    }
	    
	    
		String compactJws = Jwts.builder().setIssuer("tropo.com").setAudience("www.example.com").setSubject(email).setClaims(myClaims)
				.setIssuedAt(now).setExpiration(soon).signWith(SignatureAlgorithm.HS256, b).compact();

		// TODO: implement your handler
		return compactJws;

	}

}
