import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import { createReceivedEmail, initMailDB } from './mail.js';

// Initialize mail database
initMailDB();

const smtpServer = new SMTPServer({
  onData(stream, session, callback) {
    simpleParser(stream)
      .then(parsed => {
        // Extract recipient username from email address
        const toAddress = parsed.to.text;
        const match = toAddress.match(/^([^@]+)@/);
        if (!match) {
          return callback(new Error('Invalid recipient address'));
        }
        const recipientUsername = match[1];

        // Store the received email in database
        createReceivedEmail(
          recipientUsername,
          parsed.from.text,
          toAddress,
          parsed.subject || '',
          parsed.text || ''
        );

        console.log(`Email received for ${recipientUsername}: ${parsed.subject}`);
        callback();
      })
      .catch(err => {
        console.error('Error parsing email:', err);
        callback(err);
      });
  },
  onAuth(auth, session, callback) {
    // Allow any authentication for now (in production, implement proper auth)
    callback(null, { user: auth.username });
  },
  disabledCommands: ['STARTTLS'], // Disable TLS for simplicity
  allowInsecureAuth: true,
  authOptional: true
});

const SMTP_PORT = process.env.SMTP_PORT || 2525; // Use non-standard port to avoid conflicts

function startSMTPServer(port) {
  smtpServer.listen(port, () => {
    console.log(`📧 SMTP server listening on port ${port}`);
  }).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} is busy, trying port ${port + 1}...`);
      startSMTPServer(port + 1);
    } else {
      console.error('SMTP server error:', err);
      process.exit(1);
    }
  });
}

startSMTPServer(SMTP_PORT);
console.log('SMTP server process started');
