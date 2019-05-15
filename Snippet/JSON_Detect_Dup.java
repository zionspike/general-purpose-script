/*
 * Created: 15.05.2019 
 * 
 * Copyright (C) 2019 Juttikhun Khamchaiyaphum (juttikhun@gmail.com) 
 *
 * 
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License 
 * as published by the Free Software Foundation; either version 2 
 * of the License, or (at your option) any later version. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details. 
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA. 
 */

import java.io.IOException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;


class JSON_Detect_Dup {

	/* Malicious JSON String */
	
	private static final String s = "{\"field1\":1,\"field1\":2,\"map\":{\"1\":{\"fieldA\":\"null\",\"fieldB\":\"2\"},\"1\":{\"fieldX\":\"null\",\"fieldY\":\"2\"}}}";
	
	/* Normal JSON String */
//	private static final String s = "\"{\\\"field1\\\":1,\\\"map\\\":{\\\"1\\\":{\\\"fieldA\\\":\\\"null\\\",\\\"fieldB\\\":\\\"2\\\"}}}\"";
	public static void main(String[] args) throws IOException {
    	
    	try {
        	
    		ObjectMapper mapper = new ObjectMapper();
        	mapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        	Object result = mapper.readValue(s, Object.class);
        	System.out.println(result);
        	
    	} catch (Exception e) {
    		System.out.println("[!]" + e.getMessage());
    	}
    }
}