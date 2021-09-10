package com.mazzo.keycloak.encryption;

import javax.persistence.AttributeConverter;

/**
 * JPA Converter class used to encrypt and decrypt String columns data.
 * 
 * @author Mazen Aissa
 */
public class StringColumnConverter implements AttributeConverter<String, String> {
    
	public String convertToDatabaseColumn(String attribute) {
		return ColumnEncryptionUtility.encrypt(attribute);
	}

	public String convertToEntityAttribute(String dbData) {
		return ColumnEncryptionUtility.decrypt(dbData);
	}

}
