const myConsts = require('./webhooks/myConstants.js');
const cjs = require('crypto-js');
const http = require('http');
const LoremIpsum = require("lorem-ipsum").LoremIpsum;
const crypto = require('crypto');
const fs = require('fs');

const lorem = new LoremIpsum({
  sentencesPerParagraph: {
    max: 8,
    min: 4
  },
  wordsPerSentence: {
    max: 16,
    min: 4
  }
});

// Node.js program to demonstrate the    
// crypto.createCipheriv() method
 
// Defining algorithm
const algorithm = 'aes-256-cbc';
 
// Defining key
//const key = fs.readFileSync('key.dat');
 
// Defining iv
//const iv = fs.readFileSync('vector.dat');
 
// An encrypt function
function encrypt(text, k, v) {
 
 // Creating Cipheriv with its parameter
 //let cipher = crypto.createCipheriv(algorithm, Buffer.from(k), v);
 let cipher = crypto.createCipheriv(algorithm, k, v);
 
 // Updating text
 let encrypted = cipher.update(text);
 
 // Using concatenation
 encrypted = Buffer.concat([encrypted, cipher.final()]);
 
 // Returning iv and encrypted data
 return encrypted.toString('base64');
}

function decrypt(text, k, v) {
 
 // Creating Cipheriv with its parameter
// let decipher = crypto.createDecipheriv(algorithm, Buffer.from(k), v);
  let decipher = crypto.createDecipheriv(algorithm, k, v);
 // Updating text
 let decrypted = decipher.update(Buffer.from(text, 'base64'));
 
 // Using concatenation
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 
 // Returning iv and encrypted data
 return decrypted.toString('utf8');
}

http.createServer(function (req, res) {
	let helpMsg = "Valid endpoints:\r\nPOST /encrypt\r\nPOST /decrypt\r\nGET /encrypt\r\nGET accepts plaintext. POSTS expect plaintext body.\r\n";
	let textIn = '';
	let pwdIn = req.headers['x-crypto-pass'] != null ? req.headers['x-crypto-pass'] : myConsts.PASSPHRASE;
	
	//Hash the password into buffers for IV and Key
	let vectorHash = crypto.createHash('md5');
	vectorHash.update(pwdIn);
	let myVector = vectorHash.digest();
	
	let keyHash = crypto.createHash('sha256');
	keyHash.update(pwdIn);
	let myKey = keyHash.digest();
	
	try
	{
		req.on("data", (chunk) => { textIn += chunk; });
		req.on("end", () => {
			try
			{
				//console.log("Original text:\r\n" + textIn);
				if (req.method == "POST" && req.headers['content-type'] == "text/plain")
				{
					//console.log(req);
					if (req.url == "/encrypt")
					{
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(cjs.AES.encrypt(textIn, pwdIn).toString() + "\r\n");
						res.end();
						//console.log(res);
					}
					else if (req.url == "/decrypt")
					{
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(cjs.AES.decrypt(textIn, pwdIn).toString(cjs.enc.Utf8) + "\r\n");
						res.end();
						//console.log(res);
					}
					else if (req.url == "/aes_encrypt")
					{
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(encrypt(textIn, myKey, myVector) + "\r\n");
						res.end();
						//console.log(res);
					}
					else if (req.url == "/aes_decrypt")
					{
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(decrypt(textIn, myKey, myVector) + "\r\n");
						res.end();
						//console.log(res);
					}
					else
					{
						res.writeHead(404, {'Content-Type': 'text/plain'});
						res.write(helpMsg);
						res.end();
						
					}
				}
				else if (req.method == "GET" && req.headers['accept'] == 'text/plain')
				{
					if (req.url == "/encrypt")
					{
						textIn = lorem.generateParagraphs(1);
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(cjs.AES.encrypt(textIn, pwdIn).toString() + "\r\n");
						res.end();
					}
					else if (req.url == "/aes_encrypt")
					{
						textIn = lorem.generateParagraphs(1);
						res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
						res.write(encrypt(textIn, myKey, myVector) + "\r\n");
						res.end();
					}
				}
				else if (req.headers['Accept'] != "text/plain")
				{
					res.writeHead(415, {'Content-Type': 'text/plain'});
					res.write(helpMsg);
					res.end();
				}
				else
				{
					res.writeHead(405, {'Content-Type': 'text/plain'});
					res.write(helpMsg);
					res.end();
				}
			}
			catch(e) {
				res.writeHead(401, {'Content-Type': 'text/plain'});
				res.write(`${e.message}: Password probably invalid!\r\n`);
				res.end();
			}
		});
	}
	catch (e) {
		console.log(e.message);
	}
	
	req.on('error', (e) => {
			console.error(`problem with request: ${e.message}`);
	});
	
	res.on('error', (e) => {
			console.error(`problem with response: ${e.message}`);
	});
}).listen(9843);