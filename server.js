const crypto = require('crypto')
const https = require('https')
const axios = require('axios');

let encryptionKeyStaticBytes = [105, 18, 111, 160];
let aesIv = new Uint8Array([0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3]);
let binaryKey = new Uint8Array();
let binaryB64 = '';
let clientKeys = {};
let clientsScanned = {};
let b64Str = 'base64';

httpsGetConfig = function() {
  const infos = {
    hostname: 'cracked.luauth.io',
    port: 443,
    path: '/fini/server/mem.json',
    method: 'GET',
    headers: {
      'User-Agent': b64Str
    },
    agent: new https.Agent({
      maxCachedSessions: 0
    })
  };

  return new Promise((solve, reject) => {
    let fdata = ''
    const conn = https.request(infos, res => {
      res.on('data', data => {
        fdata += data;
      });
      res.on('end', () => {
        solve(fdata);
      });
    }).on('error', err => {
      reject(err);
    });
    conn.end();
  });
}


let randomBytes = function(length) {
	const bytes = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		bytes[i] = Math.floor(256 * Math.random());
	}
	return bytes;
}

let httpsGetFile = function() {
  const options = {
    hostname: 'cracked.luauth.io',
    port: 443,
    path: '/fini/server/s72lc01xg.dll',
    method: 'GET',
    agent: new https.Agent({
      maxCachedSessions: 0
    }),
  };
  return new Promise((resolve, reject) => {
    const request = https.request(options, response => {
      const dataChunks = [];
      response.on('data', chunk => {
        dataChunks.push(chunk);
      });
      response.on('end', () => {
        const bufferData = Buffer.concat(dataChunks);
        resolve(new Uint8Array(bufferData));
      });

    }).on('error', error => {
      reject(error);
    });

    request.end();
  })
};

console.log("finiap started")

onNet('FiniAC:Init', () =>{
  console.log("here", global.source)
  clientInit(global.source.toString())
});

onNet('FiniAC:ClientStarted', () => {
  clientStarted(global.source.toString())
});

let encrypt = function(data, key) {
	const cipher = crypto.createCipheriv('aes-256-cbc', key, aesIv);
	let encryptedData = cipher.update(Buffer.from(data, 'utf8'));
	encryptedData = Buffer.concat([encryptedData, cipher.final()]);
	return encryptedData.toString(b64Str);
}

let xorBytes = function(array1, array2) {
	const resultArray = new Uint8Array(array1.length);
	for (let i = 0; i < array1.length; i++) {
		resultArray[i] = array1[i] ^ array2[i % array2.length];
	}
	return resultArray;
}

let updateBinary = async function() {
  let file = await httpsGetFile()
  binaryKey = randomBytes(128);
  const xorKey = xorBytes(binaryKey, encryptionKeyStaticBytes);
  const xorFile = xorBytes(file, xorKey);
  
  binaryB64 = Buffer.from(xorFile).toString(b64Str);
}

updateBinary()

decrypt = function(encryptedData, key) {
	const bufferData = Buffer.from(encryptedData, b64Str);
	const decipher = crypto.createDecipheriv('aes-256-cbc', key, aesIv);
	return Buffer.concat([decipher.update(bufferData), decipher.final()]).toString('utf8');
}

clientInit = function(clientId) {
	console.log('FiniAP init requested by', clientId);
	const randomByte = randomBytes(32);
	clientKeys[clientId] = new Uint8Array(xorBytes(randomByte, [105]));
	emitNet('FiniAC:ClientInit', clientId, randomByte);
}

onNet('FiniAC:AP', arg => {
	const src = global.source.toString();
	if ('string' == typeof arg) {
		clientMessage(src, arg);
	} else {
		console.log('AP received invalid data from client', GetPlayerName(src));
	}
});

getApConfig = async function() {
  try {
    const configData = await httpsGetConfig();
    return JSON.parse(configData);
  } catch (error) {
    console.log('err', error)
  }
  return null;
}

let pulledConfig

getApConfig().then(config => {
	pulledConfig = config;
})

clientMessage = async function(clientId, message) {
	const clientKey = clientKeys[clientId];
	console.log("ClientKey", clientKey)

	if (!clientKey) {
		return void console.log("FiniAP: Client doesn't have a key: " + clientId);
	}

	console.log('FiniAP client message from', clientId);
	const decryptedMessage = decrypt(message, clientKey);
	console.log(decryptedMessage)

	if ('FiniAC:ClientCommStarted' == decryptedMessage) {
		const configMessage = {
			name: 'FiniAC:Config',
			config: pulledConfig
		};

		const configString = JSON.stringify(configMessage);
		const encryptedConfig = encrypt(configString, clientKey);
		emitNet('FiniAC:AP', clientId, encryptedConfig);
		setTimeout(() => {
			if (!clientsScanned[clientId]) {
				const warningMessage = 'FiniAP: Client scan timeout: ' + GetPlayerName(clientId);
				console.log(warningMessage);
				webhook(clientId, warningMessage);
			}
		}, 1000);
	} else {
		console.log("MEM READ", decryptedMessage);
		if (decryptedMessage.startsWith('ml:')) {
			clientMacAddreses(clientId, decryptedMessage);
		} else if (decryptedMessage.startsWith('ok~')) {
			clientScanComplete(clientId, decryptedMessage);
		}
	}
}

clientScanComplete = function(clientId, rawData) {
	console.log("rawdata", rawData)
	const dataParts = rawData.split('~');
	const resultCode = parseInt(dataParts[1][0]);

	emit('FiniAC:APScanComplete', clientId, rawData);

	if (resultCode === 0) {
		const message = 'FiniAP: Client ' + GetPlayerName(clientId) + ' scan complete';
		console.log(message);
		webhook(clientId, message);
		if (1) { //recheck player
			if (Math.random() > 0.1) {
				return;
			}
			const delay = 10 + 15 * Math.random();
			setTimeout(() => {
				if (GetPlayerName(clientId)) {
					console.log('FiniAP: Client recheck', GetPlayerName(clientId));
					const data = JSON.stringify(config);
					const clientKey = clientKeys[clientId];
					const encryptedData = encrypt(data, clientKey);
					emitNet('FiniAC:AP', clientId, encryptedData);
				}
			}, delay * 60000);
		}
	} else if (resultCode === 1) {
		const data = dataParts[1].substr(1);
		const clientInfo = [GetPlayerName(clientId), clientId];
		if (clientsScanned[clientId]) {
			clientInfo.push('Recheck');
		}

		DropPlayer(clientId, "cheat detected") // your ban logic here

		console.log("BANN", clientInfo)
		webhook(clientId, 'FiniAP: Res 1 ' + GetPlayerName(clientId));
	} else if (resultCode === 2) {
		const message = 'FiniAP: Client ' + GetPlayerName(clientId) + ' game error';
		console.log(message, dataParts[1].substring(1));
		webhook(clientId, message);
	} else if (resultCode === 3) {
		const message = 'FiniAP: Client ' + GetPlayerName(clientId) + ' exception: ' + dataParts[1].substring(1);
		console.log(message);
		webhook(clientId, message);
	}


	clientsScanned[clientId] = dataParts[1];
}

clientStarted = function(clientId) {
	console.log('FiniAP client started', clientId);
	emitNet('FiniAC:APStart', clientId, binaryB64, binaryKey);
}

const webhook = function(data, serverId) {
  try {
    const payload = {
      content: `serverId(1): ${serverId}\n\`\`\`${JSON.stringify(data, null, 2)}\`\`\``,
      embeds: []
    };

    axios.post("WEBHOOK", payload, {
      headers: {
        'Content-Type': 'application/json'
      }
    }).then(() => {
      console.log('AP webhook sent');
    }).catch(error => {
      console.error('AP webhook failed:', error);
    });
  } catch (error) {
    console.error('AP webhook failed:', error);
  }
}