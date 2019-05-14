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

#import "NSData+CRC16.h"

@implementation NSData (CRC16)

- (NSData*)crc16 {
    const uint8_t *byte = (const uint8_t *)self.bytes;
    uint16_t length = (uint16_t)self.length;
    uint16_t res =  gen_crc16(byte, length);
    
    NSData *val = [NSData dataWithBytes:&res length:sizeof(res)];
    
    return val;
}

// Calculate CRC-16/CCITT-FALSE (little endian)
uint16_t gen_crc16(const uint8_t *data, uint16_t length){
    uint8_t i;
    uint16_t wCrc = 0xffff;
    while (length--) {
        wCrc ^= *(unsigned char *)data++ << 8;
        for (i=0; i < 8; i++)
            wCrc = wCrc & 0x8000 ? (wCrc << 1) ^ 0x1021 : wCrc << 1;
    }
    // Result is here
    wCrc = wCrc & 0xffff;
    // Reverse byte order for ARM architecture
    wCrc = (wCrc>>8) | (wCrc<<8);
    return wCrc;
}

- (NSString *)hexadecimalString
{
    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];
    if (!dataBuffer) {
        return [NSString string];
    }
    NSUInteger          dataLength  = [self length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    for (int i = 0; i < dataLength; ++i)
    {
        [hexString appendFormat:@"%02x", (unsigned int)dataBuffer[i]];
    }
    return [NSString stringWithString:hexString];
}


@end



//------ Sample Use -------
/*

NSString* str = @"00020101021129370016A000000677010111011300660000000005802TH53037646304";
NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
NSData* crc16 = [data crc16];
NSString* result = [crc16 hexadecimalString];
result = [result uppercaseString];
NSLog(@"%@",result);

*/
// Result should yield 8956
