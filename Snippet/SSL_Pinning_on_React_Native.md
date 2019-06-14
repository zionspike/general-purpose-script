## __SSL Pinning on React Native__
* Step 1 - Create the certificates
```
$ openssl s_client -showcerts -connect <your_domain>:443

in this example I used https://dummyimage.com

$ openssl s_client -showcerts -connect dummyimage.com:443

...
-----BEGIN CERTIFICATE-----
MIIFaTCCBFGgAwIBAgISBDpeXXeBQ3E8aYDXQq8GhQsjMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA2MDQxMzM5MTVaFw0x
OTA5MDIxMzM5MTVaMBkxFzAVBgNVBAMTDmR1bW15aW1hZ2UuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2/KCWRydG90R/+qxgVb6GRAflwCIxow0
9PWzBJK6wQ1fi3HIrnF3NzFbZXD7P1EJSWklLP5IjPR8YZY4LM9DWLVP3TGl6F+H
jszAvRhIiIQB9jwm0HOxeN7SrDpXbCtp1MvRByIbq8y8h8iYSdwBIuqcG4bR2D1L
i81yLD8F0g7l+NktdlZheFh8FzcVTz07+FodCI5KMGud9mbmwzIhkC4q3lIuiVwp
HsR2ukZs6a8oueHdVWjI4patvdyaLo1PgbK+OcSNPrBfVd3gRz4d00k7Ce/TCeL1
HrgLj4aRaIW+4jyNHjrka2vV9Z0TapOzm8Fp0MO0QdRTEijFLRQYowIDAQABo4IC
eDCCAnQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQLXPbGHjfKq1qwUBghmwyqP6vw
gDAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRj
MGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5v
cmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5v
cmcvMC0GA1UdEQQmMCSCDmR1bW15aW1hZ2UuY29tghJ3d3cuZHVtbXlpbWFnZS5j
b20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEwKDAmBggrBgEF
BQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEFBgorBgEEAdZ5AgQC
BIH2BIHzAPEAdwBvU3asMfAxGdiZAKRRFf93FRwR2QLBACkGjbIImjfZEwAAAWsi
7g7+AAAEAwBIMEYCIQCVWyQ6X3F7F8xghLAG3Eqn5pr/SvvHXenqr5zSrb/XmwIh
APhq8PcrYuvG1XW5Z9gtxAXs1uHum6GSG3AjhSdS3+JmAHYAKTxRllTIOWW6qlD8
WAfUt2+/WHopctykwwz05UVH9HgAAAFrIu4OwwAABAMARzBFAiA3cWJB0m8aTGVu
tErBAsu9t3SdGkihG9Y58MaIy/MfMwIhAMnmLJW1PwB8XC6Pk5tQOUdoLFFITSQX
P3+1p2p583xPMA0GCSqGSIb3DQEBCwUAA4IBAQALTnY8D83dR2jhG1C92dP0f/aj
Ii9oJayplAXzsBiVpR6R8heZiXdZwCGiGp7Afev4UuXt61AHtrtOwYubkLBlNiD6
BlBvjJpzgVFhiXQV556Kojz+EnL5mW+9NWp26F2yNCxCaIzG4cfH38CfDgKWbMeM
CGgapU9TcQ7AtBI8YPmUAyrrbZ11cvyDbXRVHeTY7EALuX/kMLyA3BLfLSNZrfAf
f7XyR2V3y9e9Yjy4ITkEMwdEcGXnzGhNhUzAWPnPGPJ4UYdA0/Zcb73eDB9F9VXg
Wc5VYflu14S+GTIOGIhLF+5C4I5+AX0bF0VWe1gIZ2319m7C6qTycDRQHW8P
-----END CERTIFICATE-----
...


in this example I also use https://eny4jdr7xtt9.x.pipedream.net to demonstrate how to pin more than one certificate

$ openssl s_client -showcerts -connect eny4jdr7xtt9.x.pipedream.net:443
...
-----BEGIN CERTIFICATE-----
MIIFfzCCBGegAwIBAgIQCi01Xx/+9geSvdoEKzrc1TANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAyMTEwMDAwMDBaFw0yMDAzMTEx
MjAwMDBaMBwxGjAYBgNVBAMMESoueC5waXBlZHJlYW0ubmV0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0lVXYMtnXmg6VtdBC9/tkWBxEopjZsusAcdx
YLy20X51IZbDTBsZT5SNpf3+2F2y3PUPrIjyEAH9I0+nbRjGaGHHI/2ro7O5c3hJ
MoKKduY1JE2rsYymuyxR2ji20rC8GSybByBATHR/G2ZUt0t8UNnqUuj3t69j+RE0
0Qr1gRYfeligbrpiOtcReu7mXTu/VYhAcX/rts1gKZpHuUdPs5qmWb7nom3Oflyk
P1ygO0tpACtECZwAQ5ZCReE8vUSMk/dTMnvlz1So3rYOp0rt6leIpXvNpNgLcHMz
MBJN2PeGq6bOb1JUL18Jk8g9gOSpVJle/w8S7NEKgyOSIvCcLwIDAQABo4ICkTCC
Ao0wHwYDVR0jBBgwFoAUWaRmBlKge5WSPKOUByeWdFv5PdAwHQYDVR0OBBYEFNoQ
E7F0DkDrFNJJE1GiPF79XoZDMDAGA1UdEQQpMCeCESoueC5waXBlZHJlYW0ubmV0
ghIqLngucmVxdWVzdGJpbi5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3Js
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglg
hkgBhv1sAQIwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYh
aHR0cDovL29jc3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipo
dHRwOi8vY3J0LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0T
AQH/BAIwADCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AKS5CZC0GFgUh7sTosxn
cAo8NZgE+RvfuON3zQ7IDdwQAAABaN3REu0AAAQDAEcwRQIhANBqJDBCFOrXrObv
sMfj2fN+zXUHz3gjuyjuz19+7YXgAiBUpdb7s10F+Pl+WLv3wWE8/QuTNIYwJluZ
MkHjx7qojAB2AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABaN3R
E7sAAAQDAEcwRQIgJRFS/lHOuStwfK4eRLJ3rL3bnEyyhW9T/sLsORHAm0ECIQCd
UMAPamOhkRdWk+/64lGtvBGHmkFkPDVK+nMpAZOQOjANBgkqhkiG9w0BAQsFAAOC
AQEAX6oekWuqHY92i8VGciNrNpeRIFvdvuIUUW5uBn8evBbSxT7Gml7MvUJ6QXhQ
2RJ9ezNmGnRK/B3xq+bEQRIZpW50AIsrq4e7fZF9NaIW39sIwpWL+4aMZI0rP5wo
OG27ICQ7kentwAR5btHulKIZ1LKu+n36JVLA2kaQSAK75oUaUKq9HrDa5KBbzFUW
av14XpCkAHgJ0LXDiMBHY9fT3ZRmia3+7JijtXMRDEJTejxmCni1jcaOhjI39y9r
EWRknm1bM6ua3WS2acAIc+Re4NXdy4wmyeobSFRhk4YmO+MBd3v6YKG6UKvjrsO5
tqSwwOoLkGDZ7g5JviLGJSTUjg==
-----END CERTIFICATE-----
...

for this example we have 2 certificates which are cert.pem and cert_requestbin.pem
```

(copy the certifcate and paste it in a file name like **cert.pem**)

certificate is usually look like the following:
```
-----BEGIN CERTIFICATE-----
MIIFaTCCBFGgAwIBAgISBDpeXXeBQ3E8aYDXQq8GhQsjMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
....
-----END CERTIFICATE-----
```

***Use the one according to your domain, usually the first one in the chain.***

* Step 2 - Convert the certificate to X.509 format
```
$ openssl x509 -in cert.pem -outform der -out cert.cer
$ openssl x509 -in cert_requestbin.pem -outform der -out cert_requestbin.cer
```

* Step 3 - Install react-native-ssl-pinning
```
npm install react-native-ssl-pinning --save
react-native link react-native-ssl-pinning
```

* Step 4 - Append config in build.gradle
```
Append 'maven { url "https://jitpack.io" }' to top level build.gradle file.

the configuration should look like:
---

allprojects {
    repositories {
        mavenLocal()
        google()
        jcenter()
        maven {
            // All of React Native (JS, Obj-C sources, Android binaries) is installed from npm
            url "$rootDir/../node_modules/react-native/android"
        }
        maven { url "https://jitpack.io" }
    }
}

---
```

* Step 4 - Usage iOS
```
Drag cert.cer to Xcode project, mark your target and 'Copy items if needed'

in our example we drag the cert.cer and place it in a new folder under /myReactApp/certificates/cert.cer

You can pin more than one certificates and place it in the same folders (actually don't need to be same folder but for easier manage files we place them in the same folder)
```

* Step 5 - Usage Android
```
Place your cert.cer files under "android/app/src/main/assets/".

You can also pin more than one certificate.
```

The following code demonstrates how to use react-native-ssl-pinning with object-to-formdata which help transform an Object to FormData object. (If you don't want to use object-to-formdata, then you have to use FormData.append() for each entries in the object). I demonstrate SSL pinning with multipart form data with HTTP request using React Native.

* Remarks
	* Normally React Native provides you a **fetch** method for sending HTTP request to a web server but **fetch** method from react-native-ssl-pinning does not support formData that has been appended an object like >> formData.append(Object) << . To fix it you have to convert an Object to formData yourself or use https://www.npmjs.com/package/object-to-formdata

```
import React, {Component} from 'react';
import FormData from 'FormData';
import {fetch, removeCookieByName} from 'react-native-ssl-pinning';

import {
	StyleSheet,
	Text, Image,
	View, TouchableOpacity, Vibration, TextInput
} from 'react-native';

class Home extends Component {
	constructor(){
		super();
		this.state = {
			email:'',
			name:'',
			photo: {}
		}
	}

	updateValue(text,field){
		if(field=='name'){
			this.setState({
				name:text,
			})
		}
		if(field=='email'){
			this.setState({
				email:text,
			})
		}
	}

	submit(){
		/* Sample: name and email received from user input */
		let collection={} // define an empty object
		collection.name=this.state.name,
		collection.email=this.state.email
		console.warn(collection);

		/* Regular way to use formData with "react-native-ssl-pinning" */
		// var formData = new FormData();
		// formData.append("name","test name");
		// formData.append("email","test@email.com");

		/* Sample of failed code when use the following line with "fetch" method from "react-native-ssl-pinning" */
		// formData.append(collection)

		/* Implement the following code to transform an Object to FormData before pass it to data of HTTP request */
		/* npm install object-to-formdata */
		const objectToFormData = require('object-to-formdata');
		const formData = objectToFormData(
			collection
		);

		var url = "https://enstf6jkivf0s.x.pipedream.net/";
		fetch(url, {
			method: "POST" ,
			body: {
				formData
			},
			sslPinning: {
				certs: ["cert","cert_requestbin"]
			},
			headers: {
				'content-type': 'multipart/form-data; charset=UTF-8',
				accept: 'application/json, text/plain, /',
				}
		})
	}


	render() {
		const { photo } = this.state
		return (
			<View style={styles.container}>
			<TextInput placeholder="Name"
				style={styles.imput}
				onChangeText={(text)=>this.updateValue(text,'name')}
			/>
			<TextInput
				placeholder="Email"
				style={styles.input}
				onChangeText={(text)=>this.updateValue(text,"email")}
			/>
			<TouchableOpacity 
				style={styles.btn}
				onPress={()=>this.submit()}
			>
				<Text>Submit</Text>
			</TouchableOpacity>
			</View>
		);
	}
}

const styles = StyleSheet.create({
	container: {
		backgroundColor: '#F5FCFF',
		flex: 1,
		justifyContent: 'center'
	},
	btn:{
		backgroundColor: 'skyblue',
		height: 40,
		color:"#fff",
		justifyContent:'center',
		alignItems:'center'
	}
});

export default Home
```

