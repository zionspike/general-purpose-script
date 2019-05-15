/*
 * Created: 29.04.2019 
 * 
 * Copyright (C) 2019 Juttikhun Khamchaiyaphum (juttikhun@gmail.com) 
 *
 * Thanks to Victor Antonovich (v.antonovich@gmail.com) 
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


/**
 * 
 * @description This class help calculate CRC-16/CCITT-FALSE on Android app for QRCode integrity verification
 *
 */
public class CRC16 {
    /** CRC initialization value */ 
    public static short INIT_VALUE = (short) 0xffff; 
 
    /**
     * Calculate next CRC value. 
     * Based on algorithm from http://www.ccsinfo.com/forum/viewtopic.php?t=24977 
     * @param crcValue current CRC value 
     * @param data data value to add to CRC 
     * @return next CRC value 
     */ 
    public static short calculate(short crcValue, byte data) { 
      short x = (short) (((crcValue >>> 8) ^ data) & 0xff); 
      x ^= (x >>> 4); 
      return (short) ((crcValue << 8) ^ (x << 12) ^ (x << 5) ^ x); 
    } 
 
    /**
     * Calculate CRC value of part of data from byte array. 
     * @param data byte array 
     * @param offset data offset to calculate CRC value 
     * @param length data length to calculate CRC value 
     * @return calculated CRC value 
     */ 
    public static short calculate(byte[] data, int offset, int length) { 
        short crcValue = INIT_VALUE; 
        int counter = length; 
        int index = offset; 
        while (counter-- > 0) { 
            crcValue = calculate(crcValue, data[index++]); 
        } 
        return crcValue; 
    } 
 
 
    /**
     * Calculate CRC value for byte array. 
     * @param data byte array to calculate CRC value 
     * @return calculated CRC value 
     */ 
    public static String calculate(byte[] data) {
        // AND with 0x0000ffff to get only last 4 digits number
    	return Integer.toHexString(calculate(data, 0, data.length) & 0x0000ffff).toString();
    }
    
    public static String padLeftZeros(String inputString, int length) {
        if (inputString.length() >= length) {
            return inputString;
        }
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append('0');
        }
        sb.append(inputString);
     
        return sb.toString();
    }
    
    public static void main(String[] args)  {
    	//String qrString = "00020101021130490016A00000067701011201151630700042825000206ref002530376454040.005802TH62120708210001146304";
    	String qrString = "00020101021129370016A000000677010111011300660000000005802TH53037646304";
    	byte[] qrBytes = qrString.getBytes();
    	System.out.println("[!] QR String:" + qrString);
    	String crc = calculate(qrBytes);
        System.out.println("[!] QR CheckSum (CRC16):" + padLeftZeros(crc, 4).toUpperCase());
    }
}
