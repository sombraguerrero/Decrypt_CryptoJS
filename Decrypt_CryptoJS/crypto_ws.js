const myConsts = require('./webhooks/myConstants.js');
const AES = require("crypto-js/aes");
const http = require('http');

http.createServer(function (req, res) {
	helpMsg = "Valid endpoints:\r\nPOST /encrypt\r\nRequest body should be in plain text.";
	textIn = '';
	
	try
	{
		req.on("data", (chunk) => {
			textIn += chunk;
		});
		req.on("end", () => {
			//console.log("Original text:\r\n" + textIn);
			if (req.method == "POST" && req.headers['content-type'] == "text/plain")
			{
				//console.log(req);
				if (req.url == "/encrypt")
				{
					res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
					res.write(AES.encrypt(textIn, myConsts.PASSPHRASE).toString());
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
			else if (req.headers['content-type'] != "text/plain")
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
		});
	}
	catch (e) {
		console.error(e.message);
	}
	
	req.on('error', (e) => {
			console.error(`problem with request: ${e.message}`);
	});
	
	res.on('error', (e) => {
			console.error(`problem with response: ${e.message}`);
	});
}).listen(9843);