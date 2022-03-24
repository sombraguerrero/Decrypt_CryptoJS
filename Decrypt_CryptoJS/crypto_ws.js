const myConsts = require('./webhooks/myConstants.js');
const cjs = require('crypto-js');
const http = require('http');
const LoremIpsum = require("lorem-ipsum").LoremIpsum;

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

http.createServer(function (req, res) {
	helpMsg = "Valid endpoints:\r\nPOST /encrypt\r\nPOST /decrypt\r\nGET /encrypt\r\nGET accepts plaintext. POSTS expect plaintext body.";
	textIn = '';
	try
	{
		req.on("data", (chunk) => { textIn += chunk; });
		req.on("end", () => {
			//console.log("Original text:\r\n" + textIn);
			if (req.method == "POST" && req.headers['content-type'] == "text/plain")
			{
				//console.log(req);
				if (req.url == "/encrypt")
				{
					res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
					res.write(cjs.AES.encrypt(textIn, myConsts.PASSPHRASE).toString());
					res.end();
					//console.log(res);
				}
				else if (req.url == "/decrypt")
				{
					res.writeHead(200, {'Transfer-Encoding':'chunked','Content-Type': 'text/plain'});
					res.write(cjs.AES.decrypt(textIn, myConsts.PASSPHRASE).toString(cjs.enc.Utf8));
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
					res.write(cjs.AES.encrypt(textIn, myConsts.PASSPHRASE).toString());
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