const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');

const server = http.createServer();
const wss = new WebSocket.Server({ server });
const targetPosition = 1000;

const flagFile = 'flag.txt';
const secretFlag = fs.readFileSync(flagFile, 'utf8').trim();

wss.on('connection', (socket) => {
    let currentPosition = 0;
    let lockFlag = false;

    const resetInterval = setInterval(() => {
        currentPosition = 0;
        lockFlag = false;
        socket.send(JSON.stringify({ action: 'reset' }));
    }, 1000);

    socket.on('message', (message) => {
        try {
            const data = JSON.parse(message);

            if (data.action === 'increment' && !lockFlag) {
                currentPosition += 100;
                socket.send(JSON.stringify({ action: 'status', position: currentPosition }));
            } else if (data.action === 'lock') {
                lockFlag = true;
                setTimeout(() => {
                    if (currentPosition >= targetPosition) {
                        socket.send(JSON.stringify({ action: 'win', flag: secretFlag }));
                    } else {
                        socket.send(JSON.stringify({ action: 'lose' }));
                    }
                    currentPosition = 0;
                    lockFlag = false;
                }, 990);
            } else if (data.action === 'manualReset') {
                currentPosition = 0;
                lockFlag = false;
            }
        } catch (e) {
            socket.send(JSON.stringify({'error': e}));
        }

    });

    socket.on('close', () => {
        clearInterval(resetInterval);
    });
});

server.listen(1329, () => {
    console.log('WebSocket server started on port 1329');
});
