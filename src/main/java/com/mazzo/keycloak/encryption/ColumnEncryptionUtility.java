package com.mazzo.keycloak.encryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;

import com.google.common.io.BaseEncoding;

/**
 * This utility class is used to encrypt and decrypt Keycloak data with
 * AES-CBC-128 algorithm.
 * 
 * @author Mazen Aissa
 */
public final class ColumnEncryptionUtility {

	private static final String secretKey = "atfhbs{@sd5-*:;/"; // 128 bit key
	private static final String initVector = "atcxhgvbsqdopmlz"; // 16 bytes IV
	private static final String cipherAlg = "AES/CBC/PKCS5PADDING";
	private static final String AES = "AES";
	private static IvParameterSpec iv;
	private static SecretKeySpec skeySpec;
	private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	private static Logger logger = Logger.getLogger(ColumnEncryptionUtility.class);

	static {
		init();
	}

	private ColumnEncryptionUtility() {
	}

	private static synchronized void init() {
		iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
		skeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), AES);
		try {
			encryptCipher = Cipher.getInstance(cipherAlg);
			encryptCipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			decryptCipher = Cipher.getInstance(cipherAlg);
			decryptCipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			logger.error(e.getMessage());
		}
	}

	public static String encrypt(String plain) {
		try {
			if (plain != null) {
				if (plain.startsWith("%") && plain.endsWith("%"))
					plain = plain.replace("%", "");
				byte[] encrypted = encryptCipher.doFinal(plain.getBytes());
				return BaseEncoding.base16().lowerCase().encode(encrypted);
			}
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			logger.error(e.getMessage());
		}

		return plain;
	}

	public static String decrypt(String encrypted) {
		try {
			if (encrypted != null && !encrypted.isEmpty()) {
				byte[] original = decryptCipher.doFinal(BaseEncoding.base16().lowerCase().decode(encrypted));
				return new String(original);
			}
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			logger.error(e.getMessage());
		}
		return encrypted;
	}

}
