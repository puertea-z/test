package com.amazon.mataveriauthlibrary.provider;

import java.util.Date;
import java.util.Map;

import com.amazon.mataveriauthlibrary.constants.MataveriAuthLibraryConstants;
import com.amazon.mataveriauthlibrary.exceptions.MataveriAuthenticationException;
import org.apache.commons.codec.binary.StringUtils;
import org.joda.time.DateTimeUtils;
import amazon.platform.config.AppConfigTree;
import com.amazon.mataveriauthlibrary.utils.SignatureUtility;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.auth.AWSCredentialsProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import com.google.common.collect.Maps;

import static com.amazon.mataveriauthlibrary.constants.MataveriAuthLibraryConstants.KMS_CLIENT_EXECUTION_TIMEOUT;


/**
 * This class provides JsonWebToken (JWT) for a client.
 *
 * <p>
 * This class is responsible for generating a JsonWebToken for a client which is used by Mataveri for checking the
 * authenticity of the client. The provided token is set in a HTTP header which is then extracted at the Proxy layer
 * for validating the request. This class can be instantiated by providing the clientId, AppConfig instance to get the
 * keyId to be used for signing the token and also the credentials to be used for authenticating requests to KMS
 * from the client.
 */
public class JwtProvider {
    private static final long EXPIRY_DURATION_IN_MILLIS = 3600000L;
    private final AWSKMS kmsClient;
    private final String kmsKeyId;


    public JwtProvider(final String clientId,
                       final AppConfigTree appConfigTree,
                       final AWSCredentialsProvider awsCredentialsProvider) {
        this.kmsKeyId = appConfigTree.findString(String.format("kmsKey.%s", clientId));
        this.kmsClient = AWSKMSClientBuilder
                .standard()
                .withCredentials(awsCredentialsProvider)
                .withClientConfiguration(
                        new ClientConfiguration()
                                .withClientExecutionTimeout(KMS_CLIENT_EXECUTION_TIMEOUT)
                )
                .build();
    }

    public JwtProvider(final AWSKMS kmsClient, final String kmsKeyId) {
        this.kmsClient = kmsClient;
        this.kmsKeyId = kmsKeyId;
    }

    /**
     * This method returns the JWT token created by using the parameters provided by client in payload of JWT.
     *
     * <p>
     * The returned token consists of three parameters - header, payload and signature. The signature param
     * represents a digital signature created by encrypting given message using a cryptographic key which is owned
     * and accessed only by the owner and trusted entities. This signature is decrypted at the receiver's
     * end using the same cryptographic key pair to verify the authenticity of the sender.
     *
     * @apiNote The token generated is in the format - "header.payload.signature"
     * Header specifies the token type. Payload consists of claims such as the timestamp at which token is issued,
     * expiration time, subject and other Mataveri specific claims like ownerId, userId, clientId, verificationType.
     * Signature is then created by extracting "header.payload" from the token, using the same as the message to be
     * used for encryption. The generated signature is then appended back to the token.
     *
     * @param ownerId - customer Id
     * @param clientId - clientId specific to a client - AWSMP
     * @param userId - user on which verification need to be done
     * @param verificationType - verification type ONBOARDING/SU_ONBOARDING/BAV
     * @param sessionExpiry - Timestamp in Millis until which session needs to be alive
     * @return JwtToken - created using the above parameters in payload
     */
    public String getJwtToken(final String ownerId,
                              final String clientId,
                              final String userId,
                              final String verificationType,
                              final long sessionExpiry,
                              final String marketplace,
                              final String businessLocation) {

        final Map<String, String> verificationHeaders = Maps.newHashMap();

        // For backward compatibility calling getJwtTokenInternal
        // TODO: Replace getJwtToken by getJwtTokenV2 once client is ready to provide specified headers
        verificationHeaders.put("Owner", ownerId);
        verificationHeaders.put("User", userId);
        verificationHeaders.put("Type", verificationType);
        verificationHeaders.put("Reason", "Onboarding");
        verificationHeaders.put("Loc", businessLocation);
        verificationHeaders.put("Client", clientId);

        return getJwtTokenV2(verificationHeaders, sessionExpiry);
    }

    public String getJwtTokenV2(final Map<String, String> verificationHeaders,
                              final long sessionExpiry) {
        final Claims claims = buildJWTClaims(sessionExpiry);
        final Map<String, Object> verificationClaims = Maps.newHashMap();
        MataveriAuthLibraryConstants.VALID_MANDATORY_HEADER_MAP.forEach((headerShortName, headerFullName)  -> {
            if (verificationHeaders.containsKey(headerShortName)) {
                verificationClaims.put(headerShortName, verificationHeaders.get(headerShortName));
            } else {
                throw new MataveriAuthenticationException("Mandatory header: " + headerShortName + " not present in request");
            }
        });

        MataveriAuthLibraryConstants.VALID_OPTIONAL_HEADER_MAP.forEach((headerShortName, headerFullName) -> {
            if (verificationHeaders.containsKey(headerShortName)) {
                verificationClaims.put(headerShortName, verificationHeaders.get(headerShortName));
            }
        });

        final String token = Jwts.builder().setClaims(claims)
                .addClaims(verificationClaims)
                .compact();

        // Generating the signature using the header and payload of JWT in format "header.payload."
        // Extracting "header.payload" from "header.payload." hence need to exclude last '.' char
        final String stringToSign = token.substring(0, token.length() - 1);
        return token + getEncodedSignature(stringToSign);
    }

    private static Claims buildJWTClaims(final long sessionExpiry) {
        final long currentTimeInMillis = DateTimeUtils.currentTimeMillis();
        final long sessionExpiryCorrected = getCorrectedSessionExpiry(currentTimeInMillis, sessionExpiry);
        return Jwts.claims()
                .setIssuedAt(new Date(currentTimeInMillis))
                .setExpiration(new Date(sessionExpiryCorrected));
    }

    private static long getCorrectedSessionExpiry(final long currentTimeInMillis, final long sessionExpiry) {

        final long difference = sessionExpiry - currentTimeInMillis;
        if( difference > EXPIRY_DURATION_IN_MILLIS ) {
            return currentTimeInMillis + EXPIRY_DURATION_IN_MILLIS;
        }
        return sessionExpiry;
    }

    private String getEncodedSignature(final String stringToSign) {
        final byte[] messageInBytes = StringUtils.getBytesUtf8(stringToSign);
        SignResult result = SignatureUtility.sign(messageInBytes, kmsClient, kmsKeyId);
        final byte[] signature = new byte[result.getSignature().remaining()];
        result.getSignature().get(signature);
        return TextCodec.BASE64URL.encode(signature);
    }

    AWSKMS getKmsClient() {
        return kmsClient;
    }
}
